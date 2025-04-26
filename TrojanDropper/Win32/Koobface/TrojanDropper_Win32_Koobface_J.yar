
rule TrojanDropper_Win32_Koobface_J{
	meta:
		description = "TrojanDropper:Win32/Koobface.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 0c 38 46 40 81 fe 00 02 00 00 } //1
		$a_01_1 = {8a 14 29 32 54 24 1c 88 11 49 48 75 f3 } //1
		$a_01_2 = {68 95 1f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}