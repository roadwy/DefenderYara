
rule Ransom_MSIL_Lycheerypt_A{
	meta:
		description = "Ransom:MSIL/Lycheerypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 52 65 63 6f 76 65 72 5f 49 6e 73 74 72 75 63 74 69 6f 6e 73 2e } //01 00  _Recover_Instructions.
		$a_00_1 = {2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 31 20 3e 20 4e 75 6c 20 26 20 44 65 6c } //01 00  /C ping 1.1.1.1 -n 1 -w 1 > Nul & Del
		$a_00_2 = {4d 00 61 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 } //01 00  MainFormRansom
		$a_80_3 = {4c 69 67 68 74 6e 69 6e 67 43 72 79 70 74 } //LightningCrypt  01 00 
		$a_80_4 = {2e 4c 49 47 48 54 4e 49 4e 47 } //.LIGHTNING  00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}