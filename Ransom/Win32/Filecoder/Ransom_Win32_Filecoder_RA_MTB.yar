
rule Ransom_Win32_Filecoder_RA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 62 6c 6f 63 6b 63 68 61 69 6e 2e 69 6e 66 6f 2f } //1 //blockchain.info/
		$a_81_1 = {5c 64 65 6c 2e 62 61 74 } //1 \del.bat
		$a_81_2 = {31 38 73 48 59 55 34 39 76 55 46 6b 36 54 4e 36 47 32 50 6a 36 44 53 43 55 7a 6b 62 4c 76 77 4a 74 } //1 18sHYU49vUFk6TN6G2Pj6DSCUzkbLvwJt
		$a_81_3 = {46 49 4c 45 53 5f 42 41 43 4b 2e 74 78 74 } //1 FILES_BACK.txt
		$a_81_4 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 your files has been encrypted
		$a_81_5 = {67 65 74 72 65 63 65 69 76 65 64 62 79 61 64 64 72 65 73 73 } //1 getreceivedbyaddress
		$a_81_6 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //1 GetAsyncKeyState
		$a_81_7 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}