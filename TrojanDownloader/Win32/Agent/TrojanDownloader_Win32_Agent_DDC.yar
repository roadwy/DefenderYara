
rule TrojanDownloader_Win32_Agent_DDC{
	meta:
		description = "TrojanDownloader:Win32/Agent.DDC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {34 00 00 00 68 74 74 70 3a 2f 2f 63 63 63 2e 61 76 6e 31 32 2e 63 6e 2f 63 63 63 2f 71 71 71 63 63 63 2f 70 6f 73 74 2e 61 73 70 3f 69 3d 37 37 } //1
		$a_03_1 = {68 1c 01 00 00 6a 00 6a 04 6a 00 6a ff e8 ?? ?? ff ff } //1
		$a_00_2 = {43 42 54 5f 53 74 72 75 63 74 5f 66 6f 72 5f 51 51 } //1 CBT_Struct_for_QQ
		$a_00_3 = {77 69 6e 64 6f 77 73 5c 61 2e 74 78 74 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}