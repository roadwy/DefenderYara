
rule Trojan_Win32_Emotet_DEP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 ab 0a 00 00 f7 f9 8b 8c 24 90 01 04 8b 84 24 90 01 04 83 c1 01 89 8c 24 90 1b 00 8a 94 14 90 01 04 30 54 08 ff 90 00 } //01 00 
		$a_81_1 = {55 37 76 4e 4f 76 73 78 50 53 34 43 51 64 35 63 59 49 4d 63 37 53 37 69 6b 39 77 55 67 78 } //00 00  U7vNOvsxPS4CQd5cYIMc7S7ik9wUgx
	condition:
		any of ($a_*)
 
}