
rule Trojan_Win32_Glupteba_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 03 81 c3 04 00 00 00 39 f3 75 ef } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_RPZ_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 31 19 41 89 f2 39 c1 75 e8 c3 81 c2 90 01 04 46 8d 1c 3b 8b 1b 81 e3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_RPZ_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 df 31 32 47 42 43 39 c2 75 e0 81 c3 01 00 00 00 c3 81 eb 01 00 00 00 8d 34 0e } //00 00 
	condition:
		any of ($a_*)
 
}