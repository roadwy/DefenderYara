
rule Worm_Win32_Koobface_AT{
	meta:
		description = "Worm:Win32/Koobface.AT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 85 38 ff ff ff 41 43 45 2e c7 85 34 ff ff ff 6d 59 73 70 66 c7 85 3c ff ff ff 43 4f c6 85 3e ff ff ff 4d } //1
		$a_01_1 = {8a 55 f7 30 11 41 38 19 75 f6 80 38 31 75 02 b3 01 } //1
		$a_01_2 = {63 61 70 74 63 68 61 20 66 69 6e 69 73 68 65 64 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}