
rule Ransom_Win32_GandCrab_AY{
	meta:
		description = "Ransom:Win32/GandCrab.AY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f 39 32 2e 36 33 2e 31 39 37 2e 34 38 2f 90 02 20 2e 65 78 65 27 2c 27 25 74 65 6d 70 25 5c 90 02 20 2e 65 78 65 27 29 3b 90 00 } //01 00 
		$a_02_1 = {53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 74 65 6d 70 25 5c 90 02 20 2e 65 78 65 27 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}