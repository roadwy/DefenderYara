
rule TrojanDropper_Win32_Koobface_M{
	meta:
		description = "TrojanDropper:Win32/Koobface.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b3 01 6a 02 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8a c3 } //1
		$a_01_1 = {68 95 1f 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}