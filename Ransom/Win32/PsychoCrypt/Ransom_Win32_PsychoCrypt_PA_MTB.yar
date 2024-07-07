
rule Ransom_Win32_PsychoCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/PsychoCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 61 00 64 00 5f 00 4d 00 65 00 21 00 5f 00 2e 00 74 00 78 00 74 00 } //1 Read_Me!_.txt
		$a_01_1 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 65 00 61 00 64 00 4d 00 65 00 5f 00 4e 00 6f 00 77 00 21 00 2e 00 68 00 74 00 61 00 } //1 \Desktop\ReadMe_Now!.hta
		$a_01_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_01_3 = {59 00 6f 00 75 00 72 00 20 00 44 00 61 00 74 00 61 00 20 00 4c 00 6f 00 63 00 6b 00 65 00 64 00 } //1 Your Data Locked
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}