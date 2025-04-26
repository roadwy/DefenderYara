
rule Trojan_Win64_DLLHijack_DC_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 05 00 00 "
		
	strings :
		$a_81_0 = {6d 70 63 6c 69 65 6e 74 2e 64 6c 6c } //5 mpclient.dll
		$a_81_1 = {48 69 6a 61 63 6b 64 6c 6c 7c 53 65 74 20 43 4f 4d 20 53 74 61 72 74 75 70 } //10 Hijackdll|Set COM Startup
		$a_81_2 = {48 69 6a 61 63 6b 64 6c 6c 7c 52 65 61 64 42 75 66 66 65 72 } //10 Hijackdll|ReadBuffer
		$a_81_3 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e } //1 Wow64DisableWow64FsRedirection
		$a_81_4 = {64 6c 6c 68 6f 73 74 2e 65 78 65 } //1 dllhost.exe
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*10+(#a_81_2  & 1)*10+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=27
 
}