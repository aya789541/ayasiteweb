var app = new Vue({
    el: '#app',
    data: {
        currentSlide: 0,
        isPreviousSlide: false,
        isFirstLoad: true,
        slides: [
            {
                headlineFirstLine: "GHG ",
                headlineSecondLine: "Insights",
                sublineFirstLine: "Calculator",
                sublineSecondLine: "GHG Emissions",
                phrase1: "Step into the driver's seat of emission analytics,",
                phrase2: "Input, calculate, & understand your natural gas GHG emissions with unparalleled precision.",
                bgImg: "img/2s.avif",
                rectImg: "img/2s.avif",
                ctaText: "Assess Emissions",
                ctaLink: "/emissionpath"
            },
            {
                headlineFirstLine: "Efficiency ",
                headlineSecondLine: "Guide",
                sublineFirstLine: "Calculator",
                sublineSecondLine: "Energy Efficiency",
                phrase1: "Boosted efficiency means optimized operations and maximized production,",
                phrase2: "Be your own gas guru. Analyze your consumption & uncover hidden savings.",
                bgImg: "img/1s.avif",
                rectImg: "img/1s.avif",
                ctaText: "Run Analysis",
                ctaLink: "/energypath"
            },
            {
                headlineFirstLine: "Hydrogen ",
                headlineSecondLine: "Edge",
                sublineFirstLine: "Demo",
                sublineSecondLine: "Hydrogen Injection",
                phrase1: "It's innovation that doesn't just look good—it sells,",
                phrase2: "Through this engaging demo, witness how this element can redefine your emission narrative.",
                bgImg: "img/3s.avif",
                rectImg: "img/3s.avif",
                ctaText: "Try the Demo",
                ctaLink: "/hydrogenone"
            }
        ]
    },
    mounted: function () {
        var productRotatorSlide = document.getElementById("app");
        var startX = 0;
        var endX = 0;

        productRotatorSlide.addEventListener("touchstart", (event) => startX = event.touches[0].pageX);

        productRotatorSlide.addEventListener("touchmove", (event) => endX = event.touches[0].pageX);

        productRotatorSlide.addEventListener("touchend", function (event) {
            var threshold = startX - endX;

            if (threshold < 150 && 0 < this.currentSlide) {
                this.currentSlide--;
            }
            if (threshold > -150 && this.currentSlide < this.slides.length - 1) {
                this.currentSlide++;
            }
        }.bind(this));
    },
    methods: {
        updateSlide(index) {
            index < this.currentSlide ? this.isPreviousSlide = true : this.isPreviousSlide = false;
            this.currentSlide = index;
            this.isFirstLoad = false;
        }
    }
})