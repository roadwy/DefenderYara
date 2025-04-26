
rule Ransom_Win32_CyberVolk_PA_MTB{
	meta:
		description = "Ransom:Win32/CyberVolk.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 76 00 65 00 6e 00 63 00 } //1 cvenc
		$a_01_1 = {43 00 79 00 62 00 65 00 72 00 56 00 6f 00 6c 00 6b 00 5f 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 CyberVolk_ReadMe.txt
		$a_03_2 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 [0-15] 20 72 61 6e 73 6f 6d 77 61 72 65 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}