
rule Trojan_BAT_Lazy_NLA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {62 20 ef 8c 77 72 58 20 90 01 03 fe 61 7d 90 01 03 04 20 90 01 03 00 38 90 01 03 ff 7e 90 01 03 04 20 90 01 03 09 65 20 90 01 03 fd 61 7d 90 01 03 04 20 90 01 03 00 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {4a 65 6f 64 70 74 71 70 73 77 63 } //00 00  Jeodptqpswc
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_NLA_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 04 18 58 13 04 38 90 01 01 00 00 00 11 03 11 04 18 5b 11 06 11 04 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 38 d8 ff ff ff 90 00 } //01 00 
		$a_01_1 = {6e 6f 64 65 66 66 65 6e 64 65 72 } //01 00  nodeffender
		$a_01_2 = {4b 44 45 20 53 6f 66 74 77 61 72 65 73 } //00 00  KDE Softwares
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Lazy_NLA_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 2d 00 00 0a 25 02 fe 90 01 04 06 73 90 01 03 0a 6f 90 01 03 0a 06 73 90 01 03 0a 02 28 90 01 03 06 6f 90 01 03 0a 02 28 90 01 03 06 90 00 } //05 00 
		$a_03_1 = {28 15 00 00 0a 0a 73 90 01 03 0a 72 90 01 03 70 06 72 90 01 03 70 28 90 01 03 0a 0b 25 17 6f 90 01 03 0a 25 17 6f 90 01 03 0a 25 72 90 01 03 70 6f 90 01 03 0a 25 72 90 01 03 70 07 28 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 6f 90 01 03 0a 28 90 01 03 0a 26 de 03 90 00 } //01 00 
		$a_01_2 = {59 50 48 55 } //00 00  YPHU
	condition:
		any of ($a_*)
 
}