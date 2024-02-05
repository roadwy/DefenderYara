
rule Trojan_Win32_Zbot_BB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_02_0 = {48 43 35 00 59 00 00 47 83 ee ff 81 f1 90 01 04 49 41 e9 2e 90 00 } //05 00 
		$a_02_1 = {84 00 43 00 8b 0d 90 01 04 8b 35 90 01 04 33 ce 89 35 90 01 04 8b 15 90 01 04 f7 da 89 15 90 01 04 8b 0d 90 01 04 81 e1 90 01 04 81 f1 90 01 04 49 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zbot_BB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {e0 32 45 00 bc 32 45 00 08 32 45 00 2c 32 45 00 00 00 00 00 e4 31 45 00 98 32 45 00 9c 31 45 00 00 00 00 00 c0 31 45 00 50 32 45 00 28 33 45 00 4c 33 45 00 74 32 } //01 00 
		$a_01_1 = {44 6f 63 74 72 69 6e 69 73 6d } //01 00 
		$a_01_2 = {46 6f 72 63 69 70 61 74 65 38 } //01 00 
		$a_01_3 = {48 61 62 69 74 75 61 74 65 64 } //00 00 
	condition:
		any of ($a_*)
 
}