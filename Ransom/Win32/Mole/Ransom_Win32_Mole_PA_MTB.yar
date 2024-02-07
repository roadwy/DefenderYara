
rule Ransom_Win32_Mole_PA_MTB{
	meta:
		description = "Ransom:Win32/Mole.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 6c 6c 20 59 6f 75 72 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 21 } //01 00  Attention! All Your data was encrypted!
		$a_00_1 = {44 45 43 52 59 50 54 2d 49 44 2d 25 73 20 6e 75 6d 62 65 72 } //01 00  DECRYPT-ID-%s number
		$a_00_2 = {25 00 73 00 5c 00 5f 00 48 00 45 00 4c 00 50 00 5f 00 49 00 4e 00 53 00 54 00 52 00 55 00 43 00 54 00 49 00 4f 00 4e 00 2e 00 54 00 58 00 54 00 } //01 00  %s\_HELP_INSTRUCTION.TXT
		$a_00_3 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //01 00  aaa_TouchMeNot_.txt
		$a_01_4 = {2e 00 46 00 49 00 4c 00 45 00 } //00 00  .FILE
	condition:
		any of ($a_*)
 
}