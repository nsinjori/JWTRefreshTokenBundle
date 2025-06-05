<?php

namespace Gesdinet\JWTRefreshTokenBundle\Security\Authenticator;

use Gesdinet\JWTRefreshTokenBundle\Request\Extractor\ExtractorInterface;
use Gesdinet\JWTRefreshTokenBundle\Exception\UnknownRefreshTokenException;
use Gesdinet\JWTRefreshTokenBundle\Exception\UnknownUserFromRefreshTokenException;
use Gesdinet\JWTRefreshTokenBundle\Security\Exception\MissingTokenException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Gesdinet\JWTRefreshTokenBundle\Security\Provider\RefreshTokenProvider;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class RefreshTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private UserCheckerInterface $userChecker,
        private string $tokenParameterName,
        private ExtractorInterface $extractor
    ) {}

    public function supports(Request $request): ?bool
    {
        return null !== $this->extractor->getRefreshToken($request, $this->tokenParameterName);
    }

    public function authenticate(Request $request): Passport
    {
        $refreshToken = $this->extractor->getRefreshToken($request, $this->tokenParameterName);

        if (null === $refreshToken) {
            throw new MissingTokenException('The refresh token could not be read from the request.');
        }

        return new SelfValidatingPassport(new UserBadge($refreshToken, function ($token) {
            if (!$this->extractor instanceof UserProviderInterface) {
                throw new \RuntimeException('User provider must be instance of RefreshTokenProvider');
            }

            $username = $this->extractor->getUsernameForRefreshToken($token);

            if (null === $username) {
                throw new UnknownRefreshTokenException(sprintf('Refresh token "%s" does not exist.', $token));
            }

            try {
                $user = $this->extractor->loadUserByUsername($username);
            } catch (UsernameNotFoundException|UserNotFoundException $e) {
                throw new UnknownUserFromRefreshTokenException(sprintf('User with refresh token "%s" does not exist.', $token), $e->getCode(), $e);
            }

            $this->userChecker->checkPreAuth($user);
            $this->userChecker->checkPostAuth($user);

            return $user;
        }));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(['error' => $exception->getMessageKey()], Response::HTTP_UNAUTHORIZED);
    }
}
