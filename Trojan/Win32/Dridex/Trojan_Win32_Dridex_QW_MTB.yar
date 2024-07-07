
rule Trojan_Win32_Dridex_QW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 47 74 6b 65 6d 76 62 } //3 FGtkemvb
		$a_81_1 = {67 6f 70 65 6d 69 64 75 79 71 77 65 72 } //3 gopemiduyqwer
		$a_81_2 = {42 79 6f 6c 64 65 65 72 46 6f 6f 72 74 } //3 ByoldeerFoort
		$a_81_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //3 kernel32.Sleep
		$a_81_4 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //3 RTTYEBHUY.pdb
		$a_81_5 = {4d 70 72 41 64 6d 69 6e 54 72 61 6e 73 70 6f 72 74 47 65 74 49 6e 66 6f } //3 MprAdminTransportGetInfo
		$a_81_6 = {77 69 6c 6c 4f 45 66 58 } //3 willOEfX
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_QW_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 47 74 6b 65 6d 76 62 } //3 FGtkemvb
		$a_81_1 = {64 64 70 65 6f 69 72 6d 6b 63 76 64 2e 64 6c 6c } //3 ddpeoirmkcvd.dll
		$a_81_2 = {56 57 65 6c 6f 73 64 72 6d 6e 63 64 77 } //3 VWelosdrmncdw
		$a_81_3 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //3 kernel32.Sleep
		$a_81_4 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //3 RTTYEBHUY.pdb
		$a_81_5 = {49 73 43 6f 6c 6f 72 50 72 6f 66 69 6c 65 56 61 6c 69 64 } //3 IsColorProfileValid
		$a_81_6 = {47 65 74 57 69 6e 64 6f 77 50 6c 61 63 65 6d 65 6e 74 } //3 GetWindowPlacement
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_QW_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {47 65 29 4d 6f 64 20 6c 65 48 } //Ge)Mod leH  3
		$a_80_1 = {4c 62 72 61 47 79 45 78 34 } //LbraGyEx4  3
		$a_80_2 = {26 54 68 75 73 20 70 3e 67 67 72 3d 69 20 63 3d 6a 6e 6f 40 20 62 65 6c 72 75 6e 7c 6d 6e } //&Thus p>ggr=i c=jno@ belrun|mn  3
		$a_80_3 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_4 = {53 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //SetProcessShutdownParameters  3
		$a_80_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //ShellExecuteExA  3
		$a_80_6 = {49 73 56 61 6c 69 64 53 69 64 } //IsValidSid  3
		$a_80_7 = {47 65 74 53 69 64 49 64 65 6e 74 69 66 69 65 72 41 75 74 68 6f 72 69 74 79 } //GetSidIdentifierAuthority  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}
rule Trojan_Win32_Dridex_QW_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.QW!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 c0 2b c7 83 ea 02 05 e1 95 ff ff 03 c3 83 fa 02 7f e7 } //10
		$a_01_1 = {02 d1 8a c2 2c 2d 0f b6 c0 6a 0a 89 44 24 10 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}