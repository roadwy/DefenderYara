
rule Ransom_MacOS_X_Ratatonilly_A{
	meta:
		description = "Ransom:MacOS_X/Ratatonilly.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 8b 44 1d 00 b9 59 b6 99 f7 31 c8 41 89 07 41 89 04 1e } //01 00 
		$a_01_1 = {48 b8 7c c5 b6 d9 06 e4 dc b6 } //02 00 
		$a_01_2 = {80 3c 0b 5f 0f 85 c1 01 00 00 48 b9 00 00 00 00 fe ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 45 0f 85 a6 01 00 00 48 b9 00 00 00 00 fd ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 4d 0f 85 8b 01 00 00 48 b9 00 00 00 00 fc ff ff ff 48 01 c1 48 c1 f9 20 80 3c 0b 44 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}