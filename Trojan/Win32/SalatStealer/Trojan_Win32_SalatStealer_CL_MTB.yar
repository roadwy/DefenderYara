
rule Trojan_Win32_SalatStealer_CL_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 44 65 63 72 79 70 74 47 65 63 6b 6f } //2 main.DecryptGecko
		$a_01_1 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 41 50 50 42 } //2 main.decryptAPPB
		$a_01_2 = {6d 61 69 6e 2e 65 6e 61 62 6c 65 50 72 69 76 69 6c 65 67 65 } //2 main.enablePrivilege
		$a_01_3 = {6d 61 69 6e 2e 66 69 6e 64 4c 73 61 73 73 50 72 6f 63 65 73 73 } //2 main.findLsassProcess
		$a_01_4 = {6d 61 69 6e 2e 67 65 74 53 79 73 74 65 6d 54 6f 6b 65 6e } //2 main.getSystemToken
		$a_01_5 = {6d 61 69 6e 2e 73 65 6c 66 44 65 6c 65 74 65 } //2 main.selfDelete
		$a_01_6 = {6d 61 69 6e 2e 47 65 74 41 70 70 42 6f 75 6e 64 4b 65 79 } //2 main.GetAppBoundKey
		$a_01_7 = {6d 61 69 6e 2e 64 65 63 72 79 70 74 44 61 74 61 45 64 67 65 } //2 main.decryptDataEdge
		$a_01_8 = {6d 61 69 6e 2e 47 65 74 43 68 72 6f 6d 69 75 6d 4d 61 73 74 65 72 4b 65 79 73 } //2 main.GetChromiumMasterKeys
		$a_01_9 = {6d 61 69 6e 2e 69 73 41 64 6d 69 6e } //2 main.isAdmin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=20
 
}