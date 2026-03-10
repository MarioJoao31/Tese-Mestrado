from manim import AddTextLetterByLetter, FadeOut, Scene, Text, UP


class MCPIntroScene(Scene):
    """Simple startup intro for the Tkinter app."""

    def construct(self) -> None:
        self.camera.background_color = "#090C16"

        title = Text("Mário Tese MCP Cyber", font_size=72)
        title.set_color_by_gradient("#00C2FF", "#7AF59A")

        self.play(AddTextLetterByLetter(title, time_per_char=0.08), run_time=2.9)
        self.wait(0.5)
        self.play(FadeOut(title, shift=0.4 * UP), run_time=0.8)
