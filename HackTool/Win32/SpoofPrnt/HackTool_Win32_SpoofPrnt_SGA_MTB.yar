
rule HackTool_Win32_SpoofPrnt_SGA_MTB{
	meta:
		description = "HackTool:Win32/SpoofPrnt.SGA!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 64 6f 77 6e 6c 6f 61 64 } //1 get_download
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_2 = {72 65 67 53 70 6f 6f 66 } //1 regSpoof
		$a_01_3 = {4b 65 79 41 75 74 68 } //1 KeyAuth
		$a_01_4 = {77 65 62 68 6f 6f 6b } //1 webhook
		$a_01_5 = {67 65 74 53 70 6f 6f 66 69 6e 67 52 65 67 69 73 74 72 79 4b 65 79 73 } //1 getSpoofingRegistryKeys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}