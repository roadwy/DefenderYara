
rule HackTool_BAT_Kmscl_A_ibt{
	meta:
		description = "HackTool:BAT/Kmscl.A!ibt,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 00 61 00 69 00 74 00 69 00 6e 00 67 00 20 00 73 00 70 00 70 00 73 00 76 00 63 00 20 00 63 00 6c 00 6f 00 73 00 65 00 } //1 Waiting sppsvc close
		$a_01_1 = {4b 00 4d 00 53 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 KMS Client
		$a_01_2 = {71 00 65 00 6d 00 75 00 2d 00 69 00 6d 00 67 00 2e 00 65 00 78 00 65 00 } //1 qemu-img.exe
		$a_01_3 = {54 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 Taskkill.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}