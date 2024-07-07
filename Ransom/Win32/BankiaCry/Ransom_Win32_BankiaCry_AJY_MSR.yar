
rule Ransom_Win32_BankiaCry_AJY_MSR{
	meta:
		description = "Ransom:Win32/BankiaCry.AJY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 61 6e 6b 69 61 43 72 79 2e 65 78 65 } //1 BankiaCry.exe
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 63 68 61 63 65 6c 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 72 61 6e 73 6f 6d 5c 72 61 6e 73 6f 6d 5c 42 61 6e 6b 69 61 43 72 79 5c 6f 62 6a 5c 78 36 34 5c 44 65 62 75 67 5c 42 61 6e 6b 69 61 43 72 79 2e 70 64 62 } //1 C:\Users\chacel\source\repos\ransom\ransom\BankiaCry\obj\x64\Debug\BankiaCry.pdb
		$a_81_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 65 6e 63 72 79 70 74 65 64 21 21 20 41 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 62 65 6c 6f 6e 67 73 20 74 6f 20 75 73 21 } //1 Your computer is encrypted!! All your data belongs to us!
		$a_81_3 = {62 61 6e 6b 69 61 2d 73 65 72 76 65 72 2e 63 6f 6d } //1 bankia-server.com
		$a_81_4 = {5c 52 45 41 44 4d 45 21 21 21 21 2e 54 58 54 } //1 \README!!!!.TXT
		$a_81_5 = {53 45 4c 45 43 54 20 53 79 73 74 65 6d 53 4b 55 4e 75 6d 62 65 72 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //1 SELECT SystemSKUNumber from Win32_ComputerSystem
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}