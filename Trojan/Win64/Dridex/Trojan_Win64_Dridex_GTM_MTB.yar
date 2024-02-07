
rule Trojan_Win64_Dridex_GTM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 70 72 41 64 6d 69 6e 55 73 65 72 47 65 74 49 6e 66 6f } //01 00  MprAdminUserGetInfo
		$a_01_1 = {63 6b 69 63 6b 69 63 6b 69 6e 67 63 6b 69 6e 67 6e 67 63 6b 69 63 6b 69 66 75 66 75 66 75 66 75 63 6b 69 66 75 63 6b } //01 00  ckickickingckingngckickifufufufuckifuck
		$a_01_2 = {77 2c 6c 65 73 38 33 44 66 58 2a 42 58 45 6e 75 79 62 64 43 5a 56 } //01 00  w,les83DfX*BXEnuybdCZV
		$a_01_3 = {31 57 6a 3e 67 70 63 2b 67 47 } //01 00  1Wj>gpc+gG
		$a_01_4 = {5e 67 6f 2f 6f 40 79 5d } //01 00  ^go/o@y]
		$a_01_5 = {4d 70 72 41 64 6d 69 6e 53 65 72 76 65 72 43 6f 6e 6e 65 63 74 } //00 00  MprAdminServerConnect
	condition:
		any of ($a_*)
 
}