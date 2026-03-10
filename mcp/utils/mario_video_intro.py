from manim import *


class MarioTeseMCP(Scene):
    def construct(self) -> None:
        self.camera.background_color = "#030712"

        accent_blue = "#22D3EE"
        accent_green = "#00FF9C"
        accent_soft = "#60A5FA"

        grid = NumberPlane(
            x_range=[-8, 8, 1],
            y_range=[-4, 4, 1],
            background_line_style={
                "stroke_color": accent_blue,
                "stroke_opacity": 0.035,
                "stroke_width": 1,
            },
            axis_config={"stroke_opacity": 0},
        ).scale(1.1)

        ring = Circle(radius=2.2, color=accent_blue, stroke_width=1.4).set_opacity(0.24)
        ring2 = Circle(radius=2.65, color=accent_soft, stroke_width=1).set_opacity(0.18)
        ring_group = VGroup(ring, ring2)

        scan_line = Line(LEFT * 7, RIGHT * 7, color=accent_blue).set_opacity(0.10).move_to(UP * 3.1)

        final_title = Text("LLM Security Attack Interface", font="DejaVu Sans", font_size=58, weight=BOLD)
        final_title.set_color_by_gradient(WHITE, accent_blue, accent_green)
        final_sub = Text("Launching dashboard...", font="DejaVu Sans Mono", font_size=23, color=GRAY_B)
        final_sub.next_to(final_title, DOWN, buff=0.35)
        glow_title = final_title.copy().set_color(accent_blue).set_opacity(0.14).scale(1.08)

        # ~4 seconds total intro focused only on the dashboard reveal.
        self.play(FadeIn(grid), FadeIn(ring_group), run_time=0.45)
        self.play(scan_line.animate.move_to(DOWN * 3.1), run_time=0.9, rate_func=linear)
        self.play(
            FadeIn(glow_title),
            FadeIn(final_title, shift=0.1 * UP),
            FadeIn(final_sub, shift=0.1 * UP),
            run_time=0.85,
        )
        self.play(
            AnimationGroup(
                ApplyWave(final_title, amplitude=0.08, run_time=0.55),
                Flash(final_title.get_center(), color=accent_blue, line_length=0.7, num_lines=14, flash_radius=2.0),
                lag_ratio=0.06,
            )
        )
        self.play(
            ring_group.animate.scale(1.05).set_opacity(0.14),
            final_title.animate.scale(1.02),
            run_time=0.3,
        )
        self.play(final_title.animate.scale(1 / 1.02), run_time=0.2)
        self.wait(0.3)
        self.play(
            FadeOut(VGroup(grid, ring_group, scan_line, final_title, final_sub, glow_title)),
            run_time=0.5,
        )
