
rule Trojan_Win32_Invader_RPV_MTB{
	meta:
		description = "Trojan:Win32/Invader.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 3b 45 0c 0f 83 21 00 00 00 0f b6 75 10 8b 45 08 8b 4d f8 0f b6 14 08 31 f2 88 14 08 8b 45 f8 83 c0 01 89 45 f8 e9 d3 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}