
rule Ransom_Win32_Reveton_U{
	meta:
		description = "Ransom:Win32/Reveton.U,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 b8 7e 2a 00 00 00 0f 85 90 01 02 00 00 8d 95 90 01 04 a1 90 01 04 8b 80 e4 2a 00 00 e8 90 01 04 8b 85 90 01 04 66 ba 50 00 90 00 } //01 00 
		$a_03_1 = {9a 02 00 00 6a 00 6a 04 8d 45 90 01 01 50 53 e8 90 01 04 40 0f 84 90 09 03 00 c7 90 00 } //01 00 
		$a_01_2 = {69 6d 70 6d 74 63 6e 67 74 2c 61 6d 6f } //00 00  impmtcngt,amo
	condition:
		any of ($a_*)
 
}