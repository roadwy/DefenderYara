
rule Trojan_Win32_Prikormka_A{
	meta:
		description = "Trojan:Win32/Prikormka.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 28 c6 84 24 90 01 04 1b c6 84 24 90 01 04 1e c6 84 24 90 01 04 1f c6 84 24 90 01 04 2b c6 84 24 90 01 04 1d c6 84 24 90 01 04 2c c6 84 24 90 01 04 21 c6 84 24 90 01 04 26 c6 84 24 90 01 04 00 8d 84 24 90 01 04 59 00 08 40 80 38 00 75 f8 90 00 } //01 00 
		$a_01_1 = {88 07 eb 09 8a 54 39 ff 32 d0 88 14 39 41 3b cb 72 db 6a 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}