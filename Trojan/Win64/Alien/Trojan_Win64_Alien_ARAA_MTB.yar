
rule Trojan_Win64_Alien_ARAA_MTB{
	meta:
		description = "Trojan:Win64/Alien.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {45 00 4d 00 42 00 45 00 44 00 44 00 45 00 44 00 5c 00 53 00 54 00 41 00 52 00 54 00 49 00 53 00 41 00 4c 00 4c 00 52 00 45 00 53 00 45 00 54 00 2e 00 58 00 4d 00 4c 00 } //02 00  EMBEDDED\STARTISALLRESET.XML
		$a_00_1 = {3e 00 41 00 55 00 54 00 4f 00 48 00 4f 00 54 00 4b 00 45 00 59 00 20 00 53 00 43 00 52 00 49 00 50 00 54 00 3c 00 } //02 00  >AUTOHOTKEY SCRIPT<
		$a_01_2 = {46 69 6e 64 52 65 73 6f 75 72 63 65 57 } //02 00  FindResourceW
		$a_01_3 = {48 8d 15 d3 e0 0d 00 48 8b cb e8 cf 54 0c 00 85 c0 74 6a } //00 00 
	condition:
		any of ($a_*)
 
}