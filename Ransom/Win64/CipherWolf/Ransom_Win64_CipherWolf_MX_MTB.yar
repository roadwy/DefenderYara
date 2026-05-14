
rule Ransom_Win64_CipherWolf_MX_MTB{
	meta:
		description = "Ransom:Win64/CipherWolf.MX!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 75 72 20 72 61 6e 73 6f 6d 77 61 72 65 20 43 69 70 68 65 72 57 6f 6c 66 20 68 61 73 20 65 6e 63 72 79 70 74 65 64 20 61 6c 6c 20 66 69 6c 65 73 2e } //5 Our ransomware CipherWolf has encrypted all files.
		$a_01_1 = {64 65 6c 65 74 65 73 68 61 64 6f 77 73 2f 61 6c 6c 2f 71 75 69 65 74 } //1 deleteshadows/all/quiet
		$a_01_2 = {73 63 68 74 61 73 6b 73 2f 63 72 65 61 74 65 2f 73 2f 74 6e } //1 schtasks/create/s/tn
		$a_01_3 = {54 65 6d 70 5c 70 61 79 6c 6f 61 64 2e 65 78 65 } //1 Temp\payload.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}