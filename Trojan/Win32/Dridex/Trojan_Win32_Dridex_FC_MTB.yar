
rule Trojan_Win32_Dridex_FC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.FC!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 08 0f b6 c1 83 f8 6a 88 4c 24 29 89 44 24 24 } //0a 00 
		$a_01_1 = {8a 08 8a 54 24 29 80 e2 d8 88 54 24 5d 0f b6 c1 3d b8 } //00 00 
	condition:
		any of ($a_*)
 
}