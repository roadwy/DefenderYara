
rule Trojan_MacOS_SuspJCModule_AP{
	meta:
		description = "Trojan:MacOS/SuspJCModule.AP,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 64 6f 63 6b 65 72 2e 73 6f 63 6b } //2 com.docker.sock
		$a_00_1 = {58 6f 72 4c 6f 67 67 65 72 } //2 XorLogger
		$a_00_2 = {43 32 43 6f 6d 6d 73 4c 6f 6f 70 } //2 C2CommsLoop
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_00_4 = {55 70 6c 6f 61 64 46 69 6c 65 } //1 UploadFile
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}