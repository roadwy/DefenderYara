
rule Trojan_MacOS_Lazarus_A_MTB{
	meta:
		description = "Trojan:MacOS/Lazarus.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {c8 02 19 4a e9 02 14 8b 28 81 00 39 1f 1d 00 72 20 fe ff 54 e9 03 15 aa f5 03 08 aa 08 1d 00 12 29 1d 00 12 2a 09 c8 1a 48 a5 08 1b e9 03 15 aa 48 ff ff 35 e8 ff ff 17 e0 03 17 aa 6d 05 00 94 f7 03 00 aa ef ff ff 17 } //01 00 
		$a_00_1 = {f5 03 08 aa 08 1d 00 12 29 1d 00 12 2a 09 c8 1a 48 a5 08 1b e9 03 15 aa 48 ff ff 35 } //01 00 
		$a_00_2 = {c9 02 08 8b 0a 05 00 91 28 81 40 39 08 01 13 4a 28 81 00 39 e8 03 0a aa 9f 02 0a eb 21 ff ff 54 } //00 00 
	condition:
		any of ($a_*)
 
}