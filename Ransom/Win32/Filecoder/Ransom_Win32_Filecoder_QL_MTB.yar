
rule Ransom_Win32_Filecoder_QL_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.QL!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 6e 6f 64 65 63 72 79 70 74 6f 72 2e 74 78 74 } //2 C:\nodecryptor.txt
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 20 59 6f 75 72 20 64 61 74 61 20 69 73 20 6c 6f 63 6b 65 64 2e } //2 All your important files have been encrypted! Your data is locked.
		$a_01_2 = {59 4f 55 20 43 41 4e 20 4e 4f 54 20 52 45 43 4f 56 45 52 20 59 4f 55 52 20 46 49 4c 45 53 } //2 YOU CAN NOT RECOVER YOUR FILES
		$a_01_3 = {49 4e 46 45 43 54 45 44 20 42 59 20 4e 4f 44 45 43 52 59 50 54 } //2 INFECTED BY NODECRYPT
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}