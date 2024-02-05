
rule Trojan_Win64_Dridex_DM_MTB{
	meta:
		description = "Trojan:Win64/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {73 64 6d 66 7c 65 72 2e 70 64 62 } //sdmf|er.pdb  03 00 
		$a_80_1 = {43 72 79 70 74 49 6d 70 6f 72 74 50 75 62 6c 69 63 4b 65 79 49 6e 66 6f } //CryptImportPublicKeyInfo  03 00 
		$a_80_2 = {23 52 6c 65 61 6f 50 3e 64 74 } //#RleaoP>dt  03 00 
		$a_80_3 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  03 00 
		$a_80_4 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  03 00 
		$a_80_5 = {4c 64 72 47 65 74 } //LdrGet  03 00 
		$a_80_6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Dridex_DM_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {64 64 67 68 33 33 64 5c } //ddgh33d\  03 00 
		$a_80_1 = {56 47 32 33 34 76 35 32 33 34 } //VG234v5234  03 00 
		$a_80_2 = {57 72 69 74 65 46 69 6c 65 45 78 } //WriteFileEx  03 00 
		$a_80_3 = {49 73 50 72 6f 63 65 73 73 49 6e 4a 6f 62 } //IsProcessInJob  03 00 
		$a_80_4 = {4d 70 72 43 6f 6e 66 69 67 49 6e 74 65 72 66 61 63 65 54 72 61 6e 73 70 6f 72 74 47 65 74 49 6e 66 6f } //MprConfigInterfaceTransportGetInfo  03 00 
		$a_80_5 = {43 4d 5f 47 65 74 5f 44 65 76 69 63 65 5f 49 6e 74 65 72 66 61 63 65 5f 4c 69 73 74 5f 53 69 7a 65 57 } //CM_Get_Device_Interface_List_SizeW  03 00 
		$a_80_6 = {48 74 74 70 41 64 64 52 65 71 75 65 73 74 48 65 61 64 65 72 73 57 } //HttpAddRequestHeadersW  03 00 
		$a_80_7 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  00 00 
	condition:
		any of ($a_*)
 
}