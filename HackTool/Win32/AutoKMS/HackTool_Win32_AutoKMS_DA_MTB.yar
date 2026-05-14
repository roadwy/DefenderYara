
rule HackTool_Win32_AutoKMS_DA_MTB{
	meta:
		description = "HackTool:Win32/AutoKMS.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 5c 76 6c 6d 63 73 64 2e 6b 6d 64 } //10 C:\\vlmcsd.kmd
		$a_81_1 = {52 65 73 74 61 72 74 69 6e 67 20 76 6c 6d 63 73 64 20 73 65 72 76 69 63 65 20 3d 3e } //1 Restarting vlmcsd service =>
		$a_81_2 = {76 6c 6d 63 73 64 20 25 73 20 73 74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 vlmcsd %s started successfully
		$a_81_3 = {76 6c 6d 63 73 64 20 25 73 20 77 61 73 20 73 68 75 74 64 6f 77 6e } //1 vlmcsd %s was shutdown
		$a_81_4 = {76 6c 6d 63 73 64 20 25 73 20 25 69 2d 62 69 74 } //1 vlmcsd %s %i-bit
		$a_81_5 = {76 6c 6d 63 73 64 20 66 6c 61 67 73 3a 25 73 } //1 vlmcsd flags:%s
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}