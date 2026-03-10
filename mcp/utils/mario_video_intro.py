from manim import *
import random
import numpy as np

class MarioTeseMCP(Scene):
    def construct(self):

        self.camera.background_color = "#030712"

        CYBER_BLUE = "#22D3EE"
        CYBER_GREEN = "#00FF9C"

        # ------------------------------------------------
        # LIGHT GRID BACKGROUND (very transparent)
        # ------------------------------------------------
        grid = NumberPlane(
            x_range=[-8,8,1],
            y_range=[-4,4,1],
            background_line_style={
                "stroke_color": CYBER_BLUE,
                "stroke_opacity": 0.03,
                "stroke_width": 1
            },
            axis_config={"stroke_opacity":0}
        ).scale(1.1)

        # ------------------------------------------------
        # NETWORK NODES (cyber style)
        # ------------------------------------------------
        nodes = VGroup()
        edges = VGroup()

        positions = [
            [-5,2,0],[-3,1,0],[-1,2,0],[1,1,0],[3,2,0],
            [-4,-1,0],[-2,-2,0],[0,-1,0],[2,-2,0],[4,-1,0]
        ]

        for p in positions:
            node = Dot(p, radius=0.05, color=CYBER_GREEN).set_opacity(0.35)
            nodes.add(node)

        connections = [
            (0,1),(1,2),(2,3),(3,4),
            (0,5),(1,6),(2,7),(3,8),(4,9)
        ]

        for a,b in connections:
            edge = Line(
                nodes[a].get_center(),
                nodes[b].get_center(),
                color=CYBER_BLUE,
                stroke_width=1
            ).set_opacity(0.15)
            edges.add(edge)

        network = VGroup(edges,nodes)

        # ------------------------------------------------
        # TERMINAL LOGS
        # ------------------------------------------------
        logs = VGroup()

        log_strings = [
            "scanning MCP interface...",
            "verifying tool permissions...",
            "detecting prompt injection...",
            "checking agent boundaries..."
        ]

        y = 3

        for log in log_strings:

            t = Text(
                log,
                font="DejaVu Sans Mono",
                font_size=16,
                color=CYBER_GREEN
            )

            t.set_opacity(0.18)
            t.move_to([-5.5,y,0])
            logs.add(t)

            y -= 0.5

        # ------------------------------------------------
        # SCANNING LINE
        # ------------------------------------------------
        scan_line = Line(
            LEFT*7,
            RIGHT*7,
            color=CYBER_BLUE
        ).set_opacity(0.08)

        scan_line.move_to(UP*3)

        # ------------------------------------------------
        # HEX CYBER SHAPES
        # ------------------------------------------------
        hex1 = RegularPolygon(
            n=6,
            radius=0.7,
            color=CYBER_BLUE
        ).set_opacity(0.08)

        hex1.move_to(RIGHT*5 + UP*2)

        hex2 = RegularPolygon(
            n=6,
            radius=0.9,
            color=CYBER_BLUE
        ).set_opacity(0.05)

        hex2.move_to(LEFT*5 + DOWN*2)

        # ------------------------------------------------
        # MAIN TITLE
        # ------------------------------------------------
        text = Text(
            "Mário Tese MCP",
            font="DejaVu Sans",
            font_size=72,
            color=WHITE,
            weight=BOLD
        )

        text.move_to(ORIGIN)

        glow = text.copy().set_color(CYBER_BLUE).scale(1.05).set_opacity(0.15)

        subtitle = Text(
            "Secure MCP Framework",
            font="DejaVu Sans Mono",
            font_size=26,
            color=GRAY_B
        )

        subtitle.next_to(text,DOWN,buff=0.4)

        underline = Line(
            LEFT*3,
            RIGHT*3,
            color=CYBER_BLUE
        ).set_opacity(0.3)

        underline.next_to(subtitle,DOWN,buff=0.25)

        # ------------------------------------------------
        # BUILD BACKGROUND
        # ------------------------------------------------
        self.play(
            FadeIn(grid),
            FadeIn(network),
            FadeIn(hex1),
            FadeIn(hex2),
            FadeIn(logs),
            run_time=0.5
        )

        # scanning animation
        self.play(
            scan_line.animate.move_to(DOWN*3),
            run_time=1,
            rate_func=linear
        )

        # ------------------------------------------------
        # TITLE
        # ------------------------------------------------
        self.play(
            FadeIn(glow),
            AddTextLetterByLetter(text,time_per_char=0.035),
            run_time=1.2
        )

        self.play(
            FadeIn(subtitle),
            Create(underline),
            run_time=0.3
        )

        # pulse
        self.play(
            text.animate.scale(1.05),
            run_time=0.15
        )

        self.play(
            text.animate.scale(1/1.05),
            run_time=0.15
        )

        self.wait(0.2)

        # ------------------------------------------------
        # OUT
        # ------------------------------------------------
        self.play(
            FadeOut(grid),
            FadeOut(network),
            FadeOut(hex1),
            FadeOut(hex2),
            FadeOut(logs),
            FadeOut(text),
            FadeOut(glow),
            FadeOut(subtitle),
            FadeOut(underline),
            run_time=0.4
        )