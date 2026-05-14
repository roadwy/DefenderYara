
rule Ransom_Win32_EXITIUM_YBF_MTB{
	meta:
		description = "Ransom:Win32/EXITIUM.YBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 00 4f 00 55 00 20 00 41 00 52 00 45 00 20 00 55 00 4e 00 44 00 45 00 52 00 20 00 41 00 54 00 54 00 41 00 43 00 4b 00 } //5 YOU ARE UNDER ATTACK
		$a_01_1 = {52 75 6e 50 61 79 6c 6f 61 64 2e 62 61 74 } //5 RunPayload.bat
		$a_01_2 = {45 78 69 74 69 75 6d 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 Exitium ransomware
		$a_01_3 = {69 6e 66 72 61 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 infra have been encrypted
		$a_01_4 = {66 69 6c 65 73 20 77 61 73 20 66 65 74 63 68 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 files was fetched and encrypted
		$a_01_5 = {52 61 6e 73 6f 6d 2e 70 64 62 } //1 Ransom.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=12
 
}