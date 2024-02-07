
rule Ransom_Win32_FileCryptor_MK_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files has been encrypted
		$a_81_1 = {63 72 79 70 74 6f 72 6d 73 67 2e 68 74 61 } //01 00  cryptormsg.hta
		$a_81_2 = {50 61 79 20 30 2e 30 30 30 32 20 42 54 43 } //01 00  Pay 0.0002 BTC
		$a_81_3 = {49 66 20 79 6f 75 20 64 6f 6e 27 74 20 77 61 6e 74 20 70 61 79 20 74 68 65 72 65 27 73 20 6e 6f 20 70 72 6f 62 6c 65 6d } //01 00  If you don't want pay there's no problem
		$a_81_4 = {79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 44 45 53 54 52 4f 59 45 44 } //00 00  your files will be DESTROYED
	condition:
		any of ($a_*)
 
}