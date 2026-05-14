
rule PWS_Win64_Vidar_CM_MTB{
	meta:
		description = "PWS:Win64/Vidar.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //2 Browser List
		$a_01_1 = {43 68 72 6f 6d 69 75 6d 20 50 6c 75 67 69 6e 73 } //2 Chromium Plugins
		$a_01_2 = {46 69 72 65 66 6f 78 20 50 6c 75 67 69 6e 73 } //2 Firefox Plugins
		$a_01_3 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //2 Wallet Rules
		$a_01_4 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //2 Loader Tasks
		$a_01_5 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //2 File Grabber Rules
		$a_01_6 = {2e 6d 65 2f 48 } //2 .me/H
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}