
rule Trojan_BAT_NjRat_AHNB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AHNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 02 00 9a fe 0e 01 00 fe 0c 00 00 fe 0c 01 00 20 02 00 00 00 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 02 00 20 01 00 00 00 d6 fe 0e 02 00 fe 0c 02 00 fe 0c 03 00 8e b7 3f } //4
		$a_01_1 = {11 09 11 0e 8f 16 00 00 01 25 71 16 00 00 01 11 0c 11 0e 91 61 d2 81 16 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}