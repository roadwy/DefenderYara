
rule Trojan_BAT_Bulz_NB_MTB{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 37 01 00 04 02 28 ?? ?? 00 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 06 26 02 16 } //5
		$a_01_1 = {56 61 6e 69 6c 6c 61 52 61 74 2e 65 78 65 } //1 VanillaRat.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Bulz_NB_MTB_2{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 06 16 20 00 04 00 00 6f 9a 00 00 0a 25 13 07 16 fe 02 13 0b 11 0b 2d c6 } //3
		$a_01_1 = {24 65 34 66 37 66 35 35 35 2d 38 61 32 33 2d 34 61 39 62 2d 39 61 33 63 2d 30 36 35 65 34 34 66 63 31 32 34 34 } //1 $e4f7f555-8a23-4a9b-9a3c-065e44fc1244
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Bulz_NB_MTB_3{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 24 00 00 0a 73 1b 00 00 0a 0c 08 07 6f 25 00 00 0a 25 26 1f 4c 28 18 00 00 06 73 26 00 00 0a 0d 09 02 1f 50 28 18 00 00 06 02 8e 69 1f 54 28 18 00 00 06 59 6f 1d 00 00 0a } //3
		$a_01_1 = {4c 6f 61 64 65 72 20 43 53 47 4f 20 76 32 2d 20 43 68 65 61 74 73 54 44 4d 2e 65 78 65 } //1 Loader CSGO v2- CheatsTDM.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_Bulz_NB_MTB_4{
	meta:
		description = "Trojan:BAT/Bulz.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 a1 00 00 0a 13 08 11 08 72 d4 07 00 70 6f a2 00 00 0a 00 11 08 72 e6 07 00 70 7e 0a 00 00 04 28 9f 00 00 0a 72 0a 08 00 70 28 91 00 00 0a 6f a3 00 00 0a } //3
		$a_01_1 = {24 62 61 64 38 65 35 35 34 2d 39 34 61 38 2d 34 62 61 30 2d 39 65 34 62 2d 37 61 63 64 36 30 65 62 39 31 33 65 } //1 $bad8e554-94a8-4ba0-9e4b-7acd60eb913e
		$a_01_2 = {50 00 49 00 4e 00 47 00 21 00 } //1 PING!
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}