package logging

import (
	mask "github.com/showa-93/go-mask"
)

func MaskString(message string) string {
	maskValue, _ := mask.String(mask.MaskTypeFilled, message)
	return maskValue
}

func RegisterMaskField(filedName string) {
	mask.RegisterMaskField(filedName, mask.MaskTypeFilled)
}

func Mask(v interface{}) (interface{}, error) {
	return mask.Mask(v)
}
