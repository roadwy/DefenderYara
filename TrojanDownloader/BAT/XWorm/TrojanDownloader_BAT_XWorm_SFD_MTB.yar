
rule TrojanDownloader_BAT_XWorm_SFD_MTB{
	meta:
		description = "TrojanDownloader:BAT/XWorm.SFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 6f 70 79 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 20 66 61 69 6c 65 64 } //2 Copying shellcode failed
		$a_81_1 = {61 6d 73 69 2e 65 78 65 } //1 amsi.exe
		$a_81_2 = {78 5f 36 34 2e 74 78 74 } //1 x_64.txt
		$a_81_3 = {53 68 6f 72 74 63 75 74 20 63 72 65 61 74 65 64 20 61 74 } //1 Shortcut created at
		$a_81_4 = {54 61 73 6b 20 63 72 65 61 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Task created successfully
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}