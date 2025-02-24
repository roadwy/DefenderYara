
rule Trojan_BAT_Skeeyah_NS_MTB{
	meta:
		description = "Trojan:BAT/Skeeyah.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 71 75 6c 69 7a 76 6e 77 77 70 63 6a 72 77 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 tqulizvnwwpcjrw.My.Resources
		$a_01_1 = {24 36 35 37 62 61 36 64 34 2d 38 38 61 32 2d 34 66 61 64 2d 38 65 65 62 2d 32 33 65 31 61 35 34 37 37 34 30 61 } //2 $657ba6d4-88a2-4fad-8eeb-23e1a547740a
		$a_01_2 = {63 61 73 61 20 35 34 } //2 casa 54
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}