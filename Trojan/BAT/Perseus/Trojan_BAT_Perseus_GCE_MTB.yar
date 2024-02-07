
rule Trojan_BAT_Perseus_GCE_MTB{
	meta:
		description = "Trojan:BAT/Perseus.GCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 33 00 64 00 42 00 51 00 55 00 4e 00 6e 00 51 00 55 00 46 00 4c 00 5a 00 30 00 46 00 42 00 51 00 55 00 4a 00 4e 00 64 00 30 00 46 00 6e 00 51 00 } //01 00  R3dBQUNnQUFLZ0FBQUJNd0FnQ
		$a_01_1 = {42 00 51 00 55 00 46 00 4c 00 5a 00 6d 00 64 00 72 00 51 00 55 00 46 00 42 00 55 00 57 00 39 00 47 00 64 00 30 00 46 00 42 00 51 00 32 00 64 00 32 00 5a 00 55 00 6c 00 } //01 00  BQUFLZmdrQUFBUW9Gd0FBQ2d2ZUl
		$a_01_2 = {4b 61 6c 61 72 69 2e 65 78 65 } //01 00  Kalari.exe
		$a_01_3 = {55 72 6c 54 6f 6b 65 6e 44 65 63 6f 64 65 } //01 00  UrlTokenDecode
		$a_01_4 = {75 73 65 69 73 75 73 } //00 00  useisus
	condition:
		any of ($a_*)
 
}