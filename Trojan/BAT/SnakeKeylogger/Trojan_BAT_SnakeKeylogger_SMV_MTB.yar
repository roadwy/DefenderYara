
rule Trojan_BAT_SnakeKeylogger_SMV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 36 62 65 62 64 35 61 63 2d 61 37 32 63 2d 34 34 62 38 2d 61 37 64 39 2d 66 30 31 63 32 61 65 37 35 36 33 35 } //1 $6bebd5ac-a72c-44b8-a7d9-f01c2ae75635
		$a_81_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_2 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}