
rule TrojanDownloader_Win32_Minix_GXZ_MTB{
	meta:
		description = "TrojanDownloader:Win32/Minix.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {46 72 61 66 61 6c 64 6e 65 20 44 69 70 70 65 6e 73 2e 65 78 65 } //Frafaldne Dippens.exe  1
		$a_80_1 = {4b 61 72 74 6f 74 65 6b 73 6f 70 6c 79 73 6e 69 6e 67 65 72 73 } //Kartoteksoplysningers  1
		$a_80_2 = {43 79 6b 65 6c 62 61 6e 65 73 20 47 6c 6f 73 73 69 6e 67 6c 79 20 42 65 73 6c 69 6d 65 } //Cykelbanes Glossingly Beslime  1
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 } //1 ShellExecuteEx
		$a_80_4 = {4e 6f 6e 72 65 74 61 72 64 61 74 69 76 65 20 53 74 6f 72 72 79 67 65 72 65 6e 20 41 6d 61 72 6f 69 64 } //Nonretardative Storrygeren Amaroid  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}