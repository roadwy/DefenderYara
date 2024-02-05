
rule Trojan_Win32_Lazy_GPC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 84 24 dc 00 00 00 33 44 24 0c 89 84 24 dc 00 00 00 } //01 00 
		$a_01_1 = {8b 84 24 dc 00 00 00 33 44 24 0c 89 84 24 dc 00 00 00 8b 8c 24 d8 00 00 00 33 4c 24 10 89 8c 24 d8 00 00 00 } //01 00 
		$a_01_2 = {8b 84 24 dc 00 00 00 33 44 24 0c 8b 8c 24 d8 00 00 00 33 4c 24 10 } //00 00 
	condition:
		any of ($a_*)
 
}