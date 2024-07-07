
rule TrojanDropper_Win32_Rovnix_D{
	meta:
		description = "TrojanDropper:Win32/Rovnix.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3c 30 33 75 09 81 3c 30 33 33 33 33 74 09 83 c0 01 3b c7 72 ea } //1
		$a_01_1 = {eb 09 66 3d 46 4a 74 0d 83 c6 14 0f b7 06 66 85 c0 75 ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}