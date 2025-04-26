
rule Trojan_Win64_Dridex_DG_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {46 46 c7 45 67 4c 5f 6e 5d 3d 11 d2 7b 1e af 21 a6 db b9 03 76 e2 69 42 4a 8f 10 ab fd 64 b7 da } //10
		$a_80_1 = {53 65 74 75 70 44 69 53 65 74 53 65 6c 65 63 74 65 64 44 72 69 76 65 72 41 } //SetupDiSetSelectedDriverA  3
		$a_80_2 = {4d 70 72 41 64 6d 69 6e 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 41 64 64 } //MprAdminInterfaceTransportAdd  3
		$a_80_3 = {55 72 6c 55 6e 65 73 63 61 70 65 41 } //UrlUnescapeA  3
		$a_80_4 = {53 74 72 54 72 69 6d 57 } //StrTrimW  3
		$a_80_5 = {48 49 43 4f 4e 5f 55 73 65 72 4d 61 72 73 68 61 6c } //HICON_UserMarshal  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}
rule Trojan_Win64_Dridex_DG_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {40 77 61 6c 6b 65 72 61 72 65 70 6c 61 63 65 64 41 75 6e 61 6e 69 6d 6f 75 73 6c 79 73 6e 4d } //3 @walkerareplacedAunanimouslysnM
		$a_81_1 = {69 6e 74 6f 35 38 77 65 62 73 69 74 65 73 } //3 into58websites
		$a_81_2 = {47 65 74 57 69 6e 64 6f 77 73 41 63 63 6f 75 6e 74 44 6f 6d 61 69 6e 53 69 64 } //3 GetWindowsAccountDomainSid
		$a_81_3 = {47 65 74 55 73 65 72 4e 61 6d 65 41 } //3 GetUserNameA
		$a_81_4 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 53 69 64 57 } //3 LookupAccountSidW
		$a_81_5 = {47 65 74 43 75 72 72 65 6e 74 48 77 50 72 6f 66 69 6c 65 57 } //3 GetCurrentHwProfileW
		$a_81_6 = {47 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 4f 77 6e 65 72 } //3 GetSecurityDescriptorOwner
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}