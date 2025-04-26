
rule Ransom_Win32_IceRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/IceRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 00 43 00 45 00 5f 00 52 00 65 00 63 00 6f 00 76 00 65 00 79 00 2e 00 74 00 78 00 74 00 } //1 ICE_Recovey.txt
		$a_01_1 = {2b 2b 2b 20 42 4c 41 43 4b 20 49 43 45 20 2b 2b 2b } //1 +++ BLACK ICE +++
		$a_01_2 = {49 43 45 22 20 65 78 74 65 6e 73 69 6f 6e } //1 ICE" extension
		$a_01_3 = {46 49 4c 45 53 20 41 52 45 20 53 54 4f 4c 45 4e 20 41 4e 44 20 45 4e 43 52 59 50 54 45 44 } //1 FILES ARE STOLEN AND ENCRYPTED
		$a_01_4 = {72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 } //1 restore your files
		$a_01_5 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 vssadmin.exe delete shadows /all /quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}