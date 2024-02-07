
rule Ransom_MSIL_Crypute_E_bit{
	meta:
		description = "Ransom:MSIL/Crypute.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {72 61 6e 73 6f 6d 77 61 72 65 2e 90 02 20 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_01_1 = {59 00 6f 00 75 00 72 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 68 00 61 00 63 00 6b 00 65 00 64 00 } //01 00  Your computer has been hacked
		$a_01_2 = {59 00 6f 00 75 00 20 00 77 00 69 00 6c 00 6c 00 20 00 68 00 61 00 76 00 65 00 20 00 74 00 6f 00 20 00 65 00 6e 00 74 00 65 00 72 00 20 00 79 00 6f 00 75 00 72 00 20 00 63 00 72 00 65 00 64 00 69 00 74 00 20 00 63 00 61 00 72 00 64 00 20 00 6e 00 75 00 6d 00 62 00 65 00 72 00 } //01 00  You will have to enter your credit card number
		$a_01_3 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b } //00 00  KeyboardHook
	condition:
		any of ($a_*)
 
}