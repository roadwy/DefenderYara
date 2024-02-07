
rule TrojanSpy_Win32_Bancos_gen_AJM{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!AJM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 55 51 4c 32 33 4b 4c 32 33 44 46 39 30 57 49 35 45 31 4a 41 53 34 36 37 4e 4d 43 58 58 } //01 00  YUQL23KL23DF90WI5E1JAS467NMCXX
		$a_01_1 = {10 44 54 43 6f 6e 66 69 67 41 63 74 69 76 61 74 65 09 54 44 54 43 6f 6e 66 69 67 90 } //00 00 
	condition:
		any of ($a_*)
 
}