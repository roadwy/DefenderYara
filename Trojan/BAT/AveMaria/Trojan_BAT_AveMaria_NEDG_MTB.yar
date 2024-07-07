
rule Trojan_BAT_AveMaria_NEDG_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6b 68 6e 68 46 49 63 2e 65 78 65 } //5 khnhFIc.exe
		$a_01_1 = {34 39 64 30 62 38 39 66 2d 31 37 37 38 2d 34 66 62 31 2d 38 31 37 65 2d 31 39 63 36 31 61 35 63 30 32 31 33 } //5 49d0b89f-1778-4fb1-817e-19c61a5c0213
		$a_01_2 = {55 32 31 68 63 6e 52 42 63 33 4e 6c 62 57 4a 73 65 51 3d 3d } //2 U21hcnRBc3NlbWJseQ==
		$a_01_3 = {52 56 4a 53 49 44 49 77 4d 44 51 36 49 41 3d 3d } //2 RVJSIDIwMDQ6IA==
		$a_01_4 = {56 57 35 6f 59 57 35 6b 62 47 56 6b 52 58 68 6a 5a 58 42 30 61 57 39 75 55 6d 56 77 62 33 4a 30 } //2 VW5oYW5kbGVkRXhjZXB0aW9uUmVwb3J0
		$a_01_5 = {55 6d 56 77 62 33 4a 30 61 57 35 6e 4c 6d 46 7a 62 58 67 3d } //2 UmVwb3J0aW5nLmFzbXg=
		$a_01_6 = {55 32 68 31 64 47 52 76 64 32 34 3d } //2 U2h1dGRvd24=
		$a_01_7 = {51 32 39 31 62 47 51 67 62 6d 39 30 49 47 52 6c 63 32 56 79 61 57 46 73 61 58 70 6c 49 48 52 6f 5a 53 42 76 59 6d 56 6a 64 41 3d 3d } //2 Q291bGQgbm90IGRlc2VyaWFsaXplIHRoZSBvYmVjdA==
		$a_01_8 = {52 32 56 30 55 32 56 79 64 6d 56 79 56 56 4a 4d } //2 R2V0U2VydmVyVVJM
		$a_01_9 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //1 SmartAssembly.HouseOfCards
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1) >=25
 
}