
rule Trojan_AndroidOS_ViceLeaker_B_MTB{
	meta:
		description = "Trojan:AndroidOS/ViceLeaker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {71 00 40 6d 00 00 0c 00 6e 10 3d 6d 00 00 0c 08 16 00 40 1f 71 20 eb 47 10 00 54 e0 6c 38 54 00 2d 38 1a 01 25 65 6e 20 fd 6c 10 00 0c 00 1a 01 88 34 71 20 e1 48 10 00 0c 00 1a 01 0a 06 6e 20 90 47 10 00 0c 05 54 e0 6c 38 22 01 a1 0b 1a 02 da 40 70 20 b9 47 21 00 12 02 46 02 05 02 6e 20 c1 47 21 00 0c 01 6e 10 ce 47 01 00 0c 01 6e 20 98 6c 10 00 54 e0 6c 38 22 01 a1 0b 1a 02 d2 70 70 20 b9 47 21 00 6e 20 c1 47 81 00 0c 01 6e 10 ce 47 01 00 0c 01 6e 20 98 6c 10 00 12 00 46 00 05 00 1a 01 d6 05 6e 20 7a 47 10 00 0a 00 38 00 38 00 54 e0 6c 38 54 00 2e 38 12 11 46 01 05 01 12 22 46 02 05 02 6e 30 dd 6c 10 02 54 e0 6c 38 54 00 2d 38 1a 01 37 47 6e 30 fa 6c 80 01 } //01 00 
		$a_00_1 = {2f 72 65 71 63 61 6c 6c 6c 6f 67 2e 70 68 70 } //01 00  /reqcalllog.php
		$a_00_2 = {33 30 63 6d 64 39 30 63 6d 69 30 33 } //00 00  30cmd90cmi03
	condition:
		any of ($a_*)
 
}