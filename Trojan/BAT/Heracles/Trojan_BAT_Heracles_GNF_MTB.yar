
rule Trojan_BAT_Heracles_GNF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {07 11 0f 07 11 0f 91 6e 11 0e 6a 61 d2 9c 11 0f 17 58 13 0f 11 0f 07 8e 69 32 e5 } //0a 00 
		$a_01_1 = {06 11 0e 06 11 0e 91 6e 11 0d 6a 61 d2 9c 11 0e 17 58 13 0e 11 0e 06 8e 69 32 e5 } //0a 00 
		$a_01_2 = {09 11 11 09 11 11 91 6e 11 10 6a 61 d2 9c 11 11 17 58 13 11 11 11 09 8e 69 32 e5 } //0a 00 
		$a_01_3 = {11 04 11 12 11 04 11 12 91 6e 11 11 6a 61 d2 9c 11 12 17 58 13 12 11 12 11 04 8e 69 32 e2 } //01 00 
		$a_80_4 = {53 68 65 6c 6c 63 6f 64 65 20 50 72 6f 63 65 73 73 20 48 6f 6c 6c 6f 77 69 6e 67 2e 65 78 65 } //Shellcode Process Hollowing.exe  00 00 
	condition:
		any of ($a_*)
 
}