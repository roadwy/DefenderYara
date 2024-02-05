
rule Trojan_Win32_Emotet_PVL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 4d f3 03 c1 99 b9 7d 1a 00 00 f7 f9 8b 45 e8 8a 4c 15 00 30 08 } //00 00 
	condition:
		any of ($a_*)
 
}