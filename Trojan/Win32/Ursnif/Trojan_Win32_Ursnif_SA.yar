
rule Trojan_Win32_Ursnif_SA{
	meta:
		description = "Trojan:Win32/Ursnif.SA,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 04 00 00 "
		
	strings :
		$a_02_0 = {ff 74 24 0c 52 ff 50 ?? 8b 54 ?? ?? 8b 48 ?? 3b 4a ?? 75 0e 8b 00 3b 02 75 08 b0 01 } //1
		$a_00_1 = {53 00 69 00 6c 00 76 00 65 00 72 00 67 00 75 00 6e 00 2e 00 64 00 6c 00 6c 00 } //5 Silvergun.dll
		$a_00_2 = {76 00 65 00 72 00 62 00 20 00 53 00 61 00 } //5 verb Sa
		$a_02_3 = {8d 44 24 18 68 ee 07 00 00 50 68 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 15 20 60 44 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 05 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_02_3  & 1)*1) >=10
 
}
rule Trojan_Win32_Ursnif_SA_2{
	meta:
		description = "Trojan:Win32/Ursnif.SA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 64 69 76 69 64 65 5c 62 72 6f 61 64 5c 48 6f 6c 65 5c 44 6f 54 68 69 72 64 2e 70 64 62 } //1 c:\divide\broad\Hole\DoThird.pdb
		$a_01_1 = {77 00 63 00 73 00 63 00 61 00 74 00 5f 00 73 00 28 00 6f 00 75 00 74 00 6d 00 73 00 67 00 2c 00 20 00 28 00 73 00 69 00 7a 00 65 00 6f 00 66 00 28 00 6f 00 75 00 74 00 6d 00 73 00 67 00 29 00 20 00 2f 00 20 00 73 00 69 00 7a 00 65 00 6f 00 66 00 28 00 6f 00 75 00 74 00 6d 00 73 00 67 00 5b 00 30 00 5d 00 29 00 29 00 } //1 wcscat_s(outmsg, (sizeof(outmsg) / sizeof(outmsg[0]))
		$a_01_2 = {6d 00 5f 00 70 00 6f 00 6c 00 69 00 63 00 79 00 2e 00 47 00 65 00 74 00 50 00 6f 00 6c 00 69 00 63 00 79 00 56 00 61 00 6c 00 75 00 65 00 } //1 m_policy.GetPolicyValue
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}