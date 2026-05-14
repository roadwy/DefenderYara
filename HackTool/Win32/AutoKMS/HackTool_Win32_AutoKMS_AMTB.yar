
rule HackTool_Win32_AutoKMS_AMTB{
	meta:
		description = "HackTool:Win32/AutoKMS!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 41 52 4e 49 4e 47 3a 20 53 69 7a 65 20 6f 66 20 52 50 43 20 70 61 79 6c 6f 61 64 20 28 4b 4d 53 20 4d 65 73 73 61 67 65 29 20 73 68 6f 75 6c 64 20 62 65 20 25 75 20 62 75 74 20 69 73 20 25 75 2e } //WARNING: Size of RPC payload (KMS Message) should be %u but is %u.  2
		$a_80_1 = {76 6c 6d 63 73 64 20 25 73 20 73 74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //vlmcsd %s started successfully  2
		$a_80_2 = {3c 3c 3c 20 49 6e 63 6f 6d 69 6e 67 20 4b 4d 53 20 72 65 71 75 65 73 74 } //<<< Incoming KMS request  2
		$a_80_3 = {4b 4d 53 20 76 25 69 2e 25 69 20 72 65 71 75 65 73 74 20 66 72 6f 6d 20 25 73 20 66 6f 72 20 25 73 } //KMS v%i.%i request from %s for %s  2
		$a_80_4 = {4b 4d 53 20 68 6f 73 74 20 63 75 72 72 65 6e 74 20 61 63 74 69 76 65 20 63 6c 69 65 6e 74 73 20 3a 20 25 75 } //KMS host current active clients : %u  2
		$a_80_5 = {2d 6b 20 3c 4b 6d 73 47 55 49 44 3e 20 55 73 65 20 63 75 73 74 6f 6d 20 4b 4d 53 20 47 55 49 44 } //-k <KmsGUID> Use custom KMS GUID  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1) >=11
 
}