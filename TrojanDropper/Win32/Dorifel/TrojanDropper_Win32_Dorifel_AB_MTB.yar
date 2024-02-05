
rule TrojanDropper_Win32_Dorifel_AB_MTB{
	meta:
		description = "TrojanDropper:Win32/Dorifel.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 38 00 00 0a 06 8e b7 18 da 16 da 17 d6 6b 28 3b 00 00 0a 5a 28 3c 00 00 0a 22 00 00 80 3f 58 6b 6c 28 3d 00 00 0a b7 13 04 08 06 11 04 93 6f 3e 00 00 0a 26 09 17 d6 0d 09 11 05 } //00 00 
	condition:
		any of ($a_*)
 
}