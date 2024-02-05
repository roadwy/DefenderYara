
rule Trojan_Win32_Dridex_FA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.FA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 94 08 f8 00 00 00 89 54 24 38 8b 84 08 94 00 00 00 89 84 24 80 00 00 00 8b 44 24 38 8b 8c 24 80 00 00 00 31 c8 89 44 24 38 8b 44 24 38 03 44 24 44 89 44 24 44 } //00 00 
	condition:
		any of ($a_*)
 
}