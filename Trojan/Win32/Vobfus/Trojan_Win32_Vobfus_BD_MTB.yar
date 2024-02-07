
rule Trojan_Win32_Vobfus_BD_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 73 63 00 3a 4f ad 33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 6f 72 } //01 00 
		$a_01_1 = {6e 00 75 00 52 00 5c 00 6e 00 6f 00 69 00 73 00 72 00 65 00 56 00 74 00 6e 00 65 00 72 00 72 00 75 00 43 00 5c 00 73 00 77 00 6f 00 64 00 6e 00 69 00 57 00 5c 00 74 00 66 00 6f 00 73 00 6f 00 72 00 63 00 69 00 4d 00 5c 00 65 00 72 00 61 00 77 00 74 00 66 00 6f 00 53 00 5c 00 55 00 43 00 4b 00 48 00 } //00 00  nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS\UCKH
	condition:
		any of ($a_*)
 
}