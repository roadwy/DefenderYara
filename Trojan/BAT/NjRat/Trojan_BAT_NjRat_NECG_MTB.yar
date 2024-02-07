
rule Trojan_BAT_NjRat_NECG_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 09 6f 3b 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 02 16 02 8e b7 6f 90 01 01 00 00 0a 0c 90 00 } //02 00 
		$a_01_1 = {52 50 46 3a 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 } //02 00  RPF:SmartAssembly
		$a_01_2 = {53 68 65 68 61 64 61 5c 44 65 73 6b 74 6f 70 5c 6e 6a 53 52 43 } //00 00  Shehada\Desktop\njSRC
	condition:
		any of ($a_*)
 
}