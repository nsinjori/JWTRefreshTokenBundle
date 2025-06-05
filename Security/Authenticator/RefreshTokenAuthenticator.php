<?php

namespace App\Security\Authenticator;

use Gesdinet\JWTRefreshTokenBundle\Model\RefreshTokenManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class RefreshTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private RefreshTokenManagerInterface $refreshTokenManager,
    ) {}

    public function supports(Request $request): ?bool
    {
        return $request->getPathInfo() === '/api/token/refresh' && $request->isMethod('POST');
    }

    public function authenticate(Request $request): Passport
    {
        $data = json_decode($request->getContent(), true);
        $refreshToken = $data['refresh_token'] ?? null;

        if (!$refreshToken) {
            throw new AuthenticationException('Refresh token missing');
        }

        $refreshTokenEntity = $this->refreshTokenManager->get($refreshToken);

        if (!$refreshTokenEntity) {
            throw new AuthenticationException('Invalid refresh token');
        }

        return new SelfValidatingPassport(new UserBadge($refreshTokenEntity->getUsername()));
    }

    public function onAuthenticationSuccess(Request $request, Response $response, string $firewallName): ?Response
    {
        return null; // Request continues
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse([
            'error' => $exception->getMessageKey()
        ], Response::HTTP_UNAUTHORIZED);
    }
}
