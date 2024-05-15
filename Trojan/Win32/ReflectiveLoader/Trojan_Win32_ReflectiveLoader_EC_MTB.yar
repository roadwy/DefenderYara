
rule Trojan_Win32_ReflectiveLoader_EC_MTB{
	meta:
		description = "Trojan:Win32/ReflectiveLoader.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_81_0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  \svchost.exe
		$a_81_1 = {48 61 6a 61 63 6b 50 61 74 68 3a 25 73 } //01 00  HajackPath:%s
		$a_81_2 = {52 75 6e 44 6f 77 6e 4c 6f 61 64 65 72 44 6c 6c } //01 00  RunDownLoaderDll
		$a_81_3 = {2f 63 20 64 65 6c } //01 00  /c del
		$a_81_4 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //01 00  SeDebugPrivilege
		$a_81_5 = {46 69 6c 65 4d 67 72 3a 3a 53 68 61 72 65 46 69 6c 65 73 49 6e 4d 65 6d 6f 72 79 } //01 00  FileMgr::ShareFilesInMemory
		$a_81_6 = {44 6f 77 6e 6c 6f 61 64 43 6c 69 65 6e 74 3a 3a 57 6f 72 6b 54 68 72 65 61 64 } //01 00  DownloadClient::WorkThread
		$a_81_7 = {50 6f 6c 69 63 79 4d 67 72 3a 3a 53 74 61 72 74 } //01 00  PolicyMgr::Start
		$a_81_8 = {50 6f 6c 69 63 79 4d 67 72 3a 3a 44 6f 77 6e 6c 6f 61 64 50 6f 6c 69 63 79 } //01 00  PolicyMgr::DownloadPolicy
		$a_81_9 = {50 6f 6c 69 63 79 4d 67 72 3a 3a 44 6f 77 6e 6c 6f 61 64 50 6f 6c 69 63 79 52 65 70 6f 6e 73 65 } //01 00  PolicyMgr::DownloadPolicyReponse
		$a_81_10 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 33 32 2e 70 64 62 } //01 00  ReflectiveLoader32.pdb
		$a_81_11 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 33 32 2e 64 6c 6c } //01 00  ReflectiveLoader32.dll
		$a_81_12 = {5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 32 30 } //00 00  _ReflectiveLoader@20
	condition:
		any of ($a_*)
 
}