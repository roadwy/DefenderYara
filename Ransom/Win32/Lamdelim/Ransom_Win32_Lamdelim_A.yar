
rule Ransom_Win32_Lamdelim_A{
	meta:
		description = "Ransom:Win32/Lamdelim.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 20 61 72 65 20 64 65 6d 61 6e 64 69 6e 67 20 3a 20 32 30 30 24 20 28 55 53 44 29 } //01 00  We are demanding : 200$ (USD)
		$a_01_1 = {59 65 73 2c 20 54 6f 20 55 6e 6c 6f 63 6b 20 59 6f 75 72 20 50 43 20 4e 6f 77 2c 20 59 6f 75 20 63 61 6e 20 32 20 74 68 69 6e 67 73 2e 20 59 6f 75 20 68 61 76 65 20 74 6f 20 70 6c 61 79 20 75 73 } //01 00  Yes, To Unlock Your PC Now, You can 2 things. You have to play us
		$a_01_2 = {54 68 61 6e 6b 73 20 66 6f 72 20 42 75 79 69 6e 67 20 74 68 65 20 50 61 73 73 63 6f 64 65 2e 20 57 69 73 68 20 79 6f 75 20 63 6f 75 6c 64 20 68 61 76 65 20 6e 6f 20 56 69 72 75 73 20 66 72 6f 6d 20 74 6f 64 61 79 2c } //01 00  Thanks for Buying the Passcode. Wish you could have no Virus from today,
		$a_01_3 = {6d 69 63 72 6f 73 6f 66 74 78 79 62 65 72 40 68 61 63 6b 69 6e 64 65 78 2e 63 6f 6d } //00 00  microsoftxyber@hackindex.com
		$a_01_4 = {00 5d } //04 00  崀
	condition:
		any of ($a_*)
 
}