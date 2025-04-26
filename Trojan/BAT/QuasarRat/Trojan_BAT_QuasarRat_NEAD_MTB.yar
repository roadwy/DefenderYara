
rule Trojan_BAT_QuasarRat_NEAD_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 00 69 00 6f 00 74 00 63 00 6a 00 6c 00 74 00 2e 00 65 00 78 00 65 00 } //5 Tiotcjlt.exe
		$a_01_1 = {65 7a 42 39 49 46 56 75 5a 58 68 77 5a 57 4e 30 5a 57 51 67 52 58 4a 79 62 33 49 3d } //2 ezB9IFVuZXhwZWN0ZWQgRXJyb3I=
		$a_01_2 = {52 57 35 68 59 6d 78 6c 56 6d 6c 7a 64 57 46 73 55 33 52 35 62 47 56 7a } //2 RW5hYmxlVmlzdWFsU3R5bGVz
		$a_01_3 = {53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 48 6f 75 73 65 4f 66 43 61 72 64 73 } //1 SmartAssembly.HouseOfCards
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}