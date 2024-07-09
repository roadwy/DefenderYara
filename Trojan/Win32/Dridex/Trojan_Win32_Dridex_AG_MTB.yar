
rule Trojan_Win32_Dridex_AG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 83 c1 63 89 b4 3b a4 e8 ff ff 83 c7 04 8b 1d ?? ?? ?? ?? 66 03 cb 0f b7 d1 89 54 24 10 81 ff 74 18 00 00 73 1e } //10
		$a_00_1 = {0f b6 c8 8b 44 24 10 0f b7 d5 2b ca 0f b7 c0 83 c1 63 2b c2 03 ce 83 c0 63 03 c1 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_AG_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 6f 6d 65 6f 6f 64 65 } //Fomeoode  3
		$a_80_1 = {44 6d 6c 6f 6f 69 72 6d 46 65 72 74 } //DmlooirmFert  3
		$a_80_2 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_3 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  3
		$a_80_4 = {53 74 72 43 61 74 42 75 66 66 57 } //StrCatBuffW  3
		$a_80_5 = {4d 70 72 43 6f 6e 66 69 67 53 65 72 76 65 72 43 6f 6e 6e 65 63 74 } //MprConfigServerConnect  3
		$a_80_6 = {41 63 71 75 69 72 65 43 72 65 64 65 6e 74 69 61 6c 73 48 61 6e 64 6c 65 57 } //AcquireCredentialsHandleW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AG_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {46 46 52 67 70 6d 64 6c 77 77 57 64 65 } //FFRgpmdlwwWde  3
		$a_80_1 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  3
		$a_80_2 = {53 68 6f 77 4f 77 6e 65 64 50 6f 70 75 70 73 } //ShowOwnedPopups  3
		$a_80_3 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  3
		$a_80_4 = {53 65 74 75 70 44 69 45 6e 75 6d 44 65 76 69 63 65 49 6e 66 6f } //SetupDiEnumDeviceInfo  3
		$a_80_5 = {68 68 6f 6f 65 77 64 61 71 73 78 } //hhooewdaqsx  3
		$a_80_6 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Dridex_AG_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //3 RTTYEBHUY.pdb
		$a_01_1 = {57 72 69 74 65 47 6c 6f 62 61 6c 50 77 72 50 6f 6c 69 63 79 } //3 WriteGlobalPwrPolicy
		$a_01_2 = {46 47 74 6b 65 6d 76 62 } //3 FGtkemvb
		$a_01_3 = {73 75 62 6d 69 73 73 69 6f 6e 73 49 6f 68 63 6c 61 73 73 77 69 74 68 69 6e 73 61 6e 64 72 61 6e 65 77 55 } //3 submissionsIohclasswithinsandranewU
		$a_01_4 = {41 34 32 2e 30 2e 32 33 31 31 2e 39 30 64 77 6f 72 47 6f 73 55 70 64 61 74 65 2c } //3 A42.0.2311.90dworGosUpdate,
		$a_01_5 = {72 72 70 6f 6f 75 65 6e 6d 76 72 77 } //3 rrpoouenmvrw
		$a_01_6 = {66 6f 72 65 6b 69 69 63 6e 64 65 73 78 77 } //3 forekiicndesxw
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3) >=21
 
}