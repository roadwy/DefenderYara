
rule Trojan_Win32_Emotet_EO{
	meta:
		description = "Trojan:Win32/Emotet.EO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 72 63 68 69 74 65 63 74 75 72 65 20 6f 66 20 74 68 65 20 41 6e 6e 6f 75 6e 63 65 6d 65 6e 74 00 6d 6f 75 73 65 2d 63 6c 69 63 6b 20 69 6e 20 67 34 20 75 73 61 67 65 } //01 00 
		$a_01_1 = {73 6d 35 69 6e 59 64 61 79 73 2e 31 39 37 65 78 74 65 6e 73 69 6f 6e 73 } //01 00 
		$a_01_2 = {6f 66 32 64 48 28 64 6f 6e 6b 65 79 29 34 35 35 33 34 32 39 49 66 20 69 6e 69 74 69 61 6c 2d 66 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}