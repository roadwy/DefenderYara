
rule Trojan_BAT_NjRat_AFF_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0b 07 05 50 6f 90 01 03 0a 26 07 0e 04 6f 90 01 03 0a 26 07 0e 05 6f 90 01 03 0a 26 07 0e 06 8c 90 00 } //01 00 
		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //00 00  shell.exe
	condition:
		any of ($a_*)
 
}