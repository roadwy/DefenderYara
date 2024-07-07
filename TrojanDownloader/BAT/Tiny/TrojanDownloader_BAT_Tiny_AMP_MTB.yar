
rule TrojanDownloader_BAT_Tiny_AMP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 50 72 6f 74 6f 63 6f 6c 20 53 65 72 76 69 63 65 73 20 48 6f 73 74 2e 65 78 65 } //Microsoft Windows Protocol Services Host.exe  3
		$a_80_1 = {4d 69 63 72 6f 73 6f 66 74 20 57 69 6e 64 6f 77 73 20 50 72 6f 74 6f 63 6f 6c 20 4d 6f 6e 69 74 6f 72 2e 65 78 65 } //Microsoft Windows Protocol Monitor.exe  3
		$a_80_2 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 } //CreateDirectory  3
		$a_80_3 = {7b 41 72 67 75 6d 65 6e 74 73 20 49 66 20 4e 65 65 64 65 64 7d } //{Arguments If Needed}  3
		$a_80_4 = {53 74 61 72 74 55 70 41 70 70 } //StartUpApp  3
		$a_80_5 = {4d 69 63 72 6f 73 6f 66 74 20 53 74 61 72 74 75 70 2e 6c 6e 6b } //Microsoft Startup.lnk  3
		$a_80_6 = {43 72 65 61 74 65 53 68 6f 72 74 63 75 74 } //CreateShortcut  3
		$a_80_7 = {43 6f 70 79 32 } //Copy2  3
		$a_80_8 = {47 65 74 44 69 72 65 63 74 6f 72 79 4e 61 6d 65 } //GetDirectoryName  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}