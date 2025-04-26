
rule HackTool_BAT_AutoKms_PA2_MTB{
	meta:
		description = "HackTool:BAT/AutoKms.PA2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 72 6f 67 76 69 72 75 73 40 67 6d 61 69 6c 2e 63 6f 6d } //progvirus@gmail.com  1
		$a_80_1 = {21 21 61 37 61 70 72 6f 67 21 21 } //!!a7aprog!!  1
		$a_80_2 = {48 6f 77 20 54 6f 20 48 61 63 6b 20 45 2d 4d 61 69 6c } //How To Hack E-Mail  1
		$a_80_3 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //ShutdownMode  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}