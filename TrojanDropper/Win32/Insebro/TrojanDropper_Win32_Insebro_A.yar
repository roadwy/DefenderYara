
rule TrojanDropper_Win32_Insebro_A{
	meta:
		description = "TrojanDropper:Win32/Insebro.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d8 68 8c 00 00 00 68 90 01 04 53 e8 90 01 02 ff ff 68 8c 00 00 00 90 00 } //01 00 
		$a_01_1 = {5c 73 79 73 74 65 6d 33 32 5c 6e 65 74 2e 65 78 65 20 73 74 6f 70 20 22 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 22 } //01 00 
		$a_01_2 = {4e 61 76 69 67 61 74 69 6f 6e 20 62 6c 6f 63 6b 65 64 3c 2f 74 69 74 6c 65 3e } //00 00 
	condition:
		any of ($a_*)
 
}