
rule Trojan_Win32_Guloader_GPD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {70 69 6e 6e 75 6c 65 20 6f 62 6c 69 67 61 74 69 6f 6e 73 72 65 6e 74 65 72 6e 65 73 } //1 pinnule obligationsrenternes
		$a_81_1 = {70 69 6d 70 6c 65 64 20 76 69 73 75 61 6c 69 73 65 20 64 6f 6b 75 6d 65 6e 74 68 61 61 6e 64 74 65 72 69 6e 67 } //1 pimpled visualise dokumenthaandtering
		$a_81_2 = {73 6c 6f 74 65 2e 65 78 65 } //1 slote.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}