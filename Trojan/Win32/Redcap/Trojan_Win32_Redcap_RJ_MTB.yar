
rule Trojan_Win32_Redcap_RJ_MTB{
	meta:
		description = "Trojan:Win32/Redcap.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 32 77 69 6e 64 6f 77 73 2e 65 78 65 } //1 c2windows.exe
		$a_01_1 = {54 68 65 20 69 6e 6a 65 63 74 69 6f 6e 20 68 61 73 20 73 75 63 63 65 65 64 } //1 The injection has succeed
		$a_01_2 = {4f 6e 65 44 72 69 76 65 5c 43 6f 64 65 53 6f 75 72 63 65 5c 67 65 74 65 78 65 5f 61 6e 64 5f 72 75 6e 5c 50 72 6f 6a 65 63 74 31 5f 31 } //1 OneDrive\CodeSource\getexe_and_run\Project1_1
		$a_01_3 = {51 6a 00 6a 00 6a 04 6a 01 6a 00 6a 00 6a 00 8d 8d 70 ff ff ff 51 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}