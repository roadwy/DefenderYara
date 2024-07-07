
rule Trojan_Win32_Remcos_AA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7a 64 76 54 5f 69 31 6a 73 6f 33 76 37 4d 74 57 30 2f 65 73 2e 75 75 67 75 2e 61 2f 2f 3a 73 70 74 74 68 } //1 zdvT_i1jso3v7MtW0/es.uugu.a//:sptth
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_AA_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {67 64 65 61 64 2f 64 65 61 64 2d 6c 79 72 69 63 73 2f } //1 gdead/dead-lyrics/
		$a_81_1 = {43 68 69 6e 61 5f 43 61 74 5f 53 75 6e 66 6c 6f 77 65 72 2e 74 78 74 } //1 China_Cat_Sunflower.txt
		$a_81_2 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 \shell\open\command
		$a_81_3 = {4f 70 65 6e 41 73 5f 52 75 6e 44 4c 4c } //1 OpenAs_RunDLL
		$a_81_4 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //1 OpenClipboard
		$a_81_5 = {47 65 74 43 61 70 74 75 72 65 } //1 GetCapture
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}