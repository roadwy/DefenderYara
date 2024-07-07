
rule PWS_Win32_Tibia_AR{
	meta:
		description = "PWS:Win32/Tibia.AR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 54 1f ff 03 d3 f7 d2 88 54 18 ff 43 4e 75 e7 } //1
		$a_01_1 = {54 69 62 69 61 43 6c 69 65 6e 74 00 } //1 楔楢䍡楬湥t
		$a_03_2 = {8b 45 f8 50 6a 00 68 ff 0f 1f 00 e8 90 01 04 8d 55 fc 52 68 ff 00 00 00 8d 95 f9 fe ff ff 52 53 50 e8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}