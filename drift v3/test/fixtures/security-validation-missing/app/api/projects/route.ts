const db = { project: { create: async (_input: unknown) => ({ id: "project_1" }) } };

export async function POST(request: Request) {
  const body = await request.json();
  const project = await db.project.create({ data: body });
  return Response.json(project);
}
