define(["ramda"], function(R) {

	var Left = function(x) {
        this.__value = x;
	};

	Left.of = function(x) {
        return new Left(x);
	};

	Left.prototype.join = function(x) {
        return this.__value;
	};

	Left.prototype.map = function(f) {
        return this;
	};

	var Right = function(x) {
        this.__value = x;
	};

	Right.of = function(x) {
        return new Right(x);
	};

	Right.prototype.join = function(x) {
        return this.__value;
	};

	Right.prototype.map = function(f) {
        return Right.of(f(this.__value));
	};

	var either = R.curry(function(f, g, e) {
		switch(e.constructor) {
			case Left: return f(e.__value);
			case Right: return g(e.__value);
	  }
	});

	var IO = function(f) {
		this.unsafePerformIO = f;
	};

	IO.of = function(x) {
		return new IO(x);
	};

	IO.prototype.map = function(f) {
		return new IO(R.compose(f, this.unsafePerformIO));
	};

    IO.prototype.join = function() {
        return this.unsafePerformIO();
    };

    var map = R.curry(function(f, obj) {
        return obj.map(f);
    });

    var join = function(mma){ 
        return mma.join(); 
    };

    var chain = R.curry(function(f, m) {
          return m.map(f).join(); // or compose(join, map(f))(m)
    });

	return {
		IO: IO,
        Left: Left,
        Right: Right,
		either: either,
        map: map,
        join: join,
        chain: chain
	};
});
