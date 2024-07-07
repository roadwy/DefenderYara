
rule Ransom_Win32_Revil_SD_MTB{
	meta:
		description = "Ransom:Win32/Revil.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6b 72 65 6d 65 7a 20 61 6e 64 20 68 73 7a 72 64 20 66 75 63 6b 6f 66 66 2e 74 78 74 } //1 kremez and hszrd fuckoff.txt
		$a_81_1 = {70 6f 6c 69 73 68 20 70 72 6f 73 74 69 74 75 74 65 } //1 polish prostitute
		$a_81_2 = {45 72 72 6f 72 5f 64 6f 75 62 6c 65 5f 72 75 6e } //1 Error_double_run
		$a_81_3 = {53 65 72 76 69 63 65 73 41 63 74 69 76 65 } //1 ServicesActive
		$a_81_4 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 70 61 6e 64 20 31 36 2d 62 79 74 65 20 6b } //1 expand 32-byte kexpand 16-byte k
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}