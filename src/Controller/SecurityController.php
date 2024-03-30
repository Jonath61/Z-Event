<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Nelmio\ApiDocBundle\Annotation\{Model, Security};
use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\{JsonResponse, Request, Response};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Contracts\Service\Attribute\Required;

#[Route('/api', name: 'app_api_')]
class SecurityController extends AbstractController
{
    public function __construct(private EntityManagerInterface $manager, private SerializerInterface $serializer)
    {
    }

    #[Route('/register', name: 'register', methods: 'POST')]
    /** @OA\(
     *     path="/api/register",
     *     summary="Inscription d'un nouvel utilisateur",
     *     @OA\RequestBody(
     *         required=true,
     *         description="Données de l'utilisateur à inscrire",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="email", type="string", example="adresse@email.com"),
     *             @OA\Property(property="password", type="string", example="Mot de passe")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Utilisateur inscrit avec succès",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user", type="string", example="Nom d'utilisateur"),
     *             @OA\Property(property="apiToken", type="string", example="31a023e212f116124a36af14ea0c1c3806eb9378"),
     *             @OA\Property(property="roles", type="array", @OA\Items(type="string", example="ROLE_USER"))
     *         )
     *     )
     * )
     */

    public function register(Request $request, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $user = $this->serializer->deserialize($request->getContent(), User::class, 'json');
        $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));
        $user->setCreatedAt(new \DateTimeImmutable());

        $this->manager->persist($user);
        $this->manager->flush();

        return new JsonResponse(
            ['user' => $user->getUserIdentifier(), 'apiToken' => $user->getApiToken(), 'roles' => $user->getRoles()],
            Response::HTTP_CREATED
        );
    }

    #[Route('/login', name: 'login', methods: 'POST')]

    public function login(#[CurrentUser] ?User $user): JsonResponse
    {
        if (null === $user) {
        return new JsonResponse(['message' => 'missing credentials',], Response::HTTP_UNAUTHORIZED);
        }
        return new JsonResponse([
            'user' => $user-> getUserIdentifier(),
            'apiToken' => $user->getApiToken(),
            'roles' => $user->getRoles(),
        ]);
    }
}
