
rule Trojan_BAT_NjRat_NEBR_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {28 1b 00 00 06 0b 07 6f 32 00 00 0a 17 da 0c 16 0d 2b 1f 7e 0a 00 00 04 07 09 16 6f 33 00 00 0a 13 04 12 04 28 34 00 00 0a 6f 35 00 00 0a 09 17 d6 0d 09 08 31 dd } //05 00 
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 65 00 78 00 65 00 } //00 00  WindowsApp1.exe
	condition:
		any of ($a_*)
 
}