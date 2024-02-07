
rule Trojan_BAT_Disstl_ADS_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 73 14 00 00 0a 0b 07 6f 90 01 03 0a 72 f6 00 00 70 72 10 01 00 70 6f 90 01 03 0a 00 72 32 01 00 70 02 72 4e 01 00 70 28 90 01 03 0a 0c 07 06 28 90 00 } //01 00 
		$a_01_1 = {54 00 65 00 6d 00 70 00 5c 00 4d 00 61 00 68 00 65 00 73 00 68 00 2e 00 74 00 78 00 74 00 } //00 00  Temp\Mahesh.txt
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Disstl_ADS_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 6f 90 01 03 0a 72 c4 01 00 70 72 de 01 00 70 6f 90 01 03 0a 00 72 00 02 00 70 02 72 1c 02 00 70 28 90 01 03 0a 0c 07 06 90 00 } //01 00 
		$a_01_1 = {5c 61 64 72 69 61 5c 44 6f 77 6e 6c 6f 61 64 73 5c 44 69 73 63 6f 72 64 2d 47 72 61 62 62 65 72 2d 6d 61 69 6e 5c 47 72 61 62 62 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 72 6f 67 72 61 6d 2e 70 64 62 } //00 00  \adria\Downloads\Discord-Grabber-main\Grabber\obj\Debug\Program.pdb
	condition:
		any of ($a_*)
 
}