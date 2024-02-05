
rule Trojan_Win32_Recordbreaker_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Recordbreaker.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 85 db 0f 84 ca 00 00 00 8b 75 f4 33 c0 6a 01 50 6a 03 50 50 6a 50 58 6a 73 5a 66 3b f2 89 55 ec b9 bb 01 00 00 0f 44 c1 0f b7 c0 50 ff 75 f0 53 } //01 00 
		$a_01_1 = {85 db 0f 84 c4 00 00 00 6a 01 33 c0 b9 bb 01 00 00 50 6a 03 50 50 6a 50 58 6a 73 5a 66 39 55 e4 0f 44 c1 0f b7 c0 50 ff 75 ec 53 } //00 00 
	condition:
		any of ($a_*)
 
}