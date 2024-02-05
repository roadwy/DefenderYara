
rule TrojanDropper_Win32_Fedripto_A{
	meta:
		description = "TrojanDropper:Win32/Fedripto.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 30 74 05 80 c1 90 01 01 eb 03 80 c1 90 01 01 88 0c 30 8b 4c 24 10 40 3b c1 72 d8 90 00 } //01 00 
		$a_01_1 = {46 64 72 31 33 38 69 70 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}