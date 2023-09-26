# class ObjWrapper:
# 	"""
# 	Wraps a dict (with nested dict/list/tuple) object to act like python object (so that '.' notation works)
# 	"""
# 	@classmethod
# 	def is_my_type(cls, value):
# 		return isinstance(value, (dict, list, tuple))

# 	@classmethod
# 	def _wrap_if_needed(cls, value):
# 		if cls.is_my_type(value):
# 			return cls(value)
# 		return value

# 	def __init__(self, *args, **kwargs):
# 		if args:
# 			assert not kwargs, "Only one of *args or **kwargs can be specified at a time"
# 			assert len(args) == 1, 'Expecting exactly one argument in args'

# 			d = args[0]
# 			assert self.is_my_type(d), "Expecting a 'dict/list/tuple' instance, got {0}".format(type(d).__name__)
# 			self._data = d
# 		else:
# 			self._data = kwargs

# 	def __getattr__(self, item):
# 		return self._wrap_if_needed(self._data[item])

# 	def __getitem__(self, item):
# 		return self._wrap_if_needed(self._data[item])

# 	def __repr__(self):
# 		return str(self._data)

# 	def __str__(self):
# 		return str(self._data)

# 	def data(self):
# 		return self._data