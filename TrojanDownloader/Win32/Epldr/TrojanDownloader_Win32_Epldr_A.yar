
rule TrojanDownloader_Win32_Epldr_A{
	meta:
		description = "TrojanDownloader:Win32/Epldr.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5f 00 65 00 78 00 70 00 6c 00 6f 00 69 00 74 00 5f 00 68 00 6f 00 73 00 74 00 69 00 6e 00 67 00 5c 00 5f 00 6e 00 65 00 77 00 32 00 5f 00 64 00 77 00 6e 00 6c 00 64 00 72 00 5f 00 } //1 _exploit_hosting\_new2_dwnldr_
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 50 72 6f 67 72 65 73 73 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}