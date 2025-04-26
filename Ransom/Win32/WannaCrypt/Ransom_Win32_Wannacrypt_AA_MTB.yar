
rule Ransom_Win32_Wannacrypt_AA_MTB{
	meta:
		description = "Ransom:Win32/Wannacrypt.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 61 6e 6e 61 43 72 79 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 WannaCry Ransomware
		$a_81_1 = {59 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2e } //1 Your important files are encrypted.
		$a_81_2 = {50 61 79 6d 65 6e 74 20 69 73 20 61 63 63 65 70 74 65 64 20 69 6e 20 42 69 74 63 6f 69 6e 73 20 6f 6e 6c 79 2e } //1 Payment is accepted in Bitcoins only.
		$a_81_3 = {4c 6f 63 61 6c 20 64 72 69 76 65 2c 20 52 61 6d 20 26 20 42 6f 6f 74 6c 6f 61 64 65 72 20 42 69 6f 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Local drive, Ram & Bootloader Bios has been encrypted
		$a_81_4 = {59 6f 75 20 6e 65 65 64 20 70 61 79 20 30 2c 30 32 20 42 54 43 } //1 You need pay 0,02 BTC
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}