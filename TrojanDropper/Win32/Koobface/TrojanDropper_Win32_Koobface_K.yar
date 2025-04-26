
rule TrojanDropper_Win32_Koobface_K{
	meta:
		description = "TrojanDropper:Win32/Koobface.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 14 29 40 45 3d 00 02 00 00 } //1
		$a_01_1 = {8a 14 01 32 54 24 24 88 10 48 ff 4c 24 10 75 f0 } //1
		$a_01_2 = {68 95 1f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}