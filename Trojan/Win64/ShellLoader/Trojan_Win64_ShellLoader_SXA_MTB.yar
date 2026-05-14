
rule Trojan_Win64_ShellLoader_SXA_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 63 6f 64 65 20 4c 6f 61 64 65 72 20 53 74 61 72 74 65 64 } //10 Shellcode Loader Started
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 25 73 22 20 2f 74 72 20 22 22 25 73 22 22 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f 20 31 20 2f 73 74 20 30 30 3a 30 30 20 2f 66 } //10 schtasks /create /tn "%s" /tr ""%s"" /sc minute /mo 1 /st 00:00 /f
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 20 65 78 65 63 75 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 } //5 Shellcode execution completed
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //2 Downloading shellcode
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*2) >=27
 
}