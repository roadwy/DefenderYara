
rule Trojan_BAT_Injuke_NJ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 16 1a 28 ?? 00 00 0a 11 07 20 ?? 36 0c d0 5a 20 ?? ea 13 a0 61 38 fc fe ff ff 7e ?? 00 00 0a 2d 08 20 ?? 05 3b b4 25 2b 06 } //4
		$a_01_1 = {24 65 63 62 33 37 31 31 61 2d 65 38 39 36 2d 34 65 37 63 2d 61 66 62 33 2d 33 63 66 32 30 32 36 37 32 63 63 39 } //1 $ecb3711a-e896-4e7c-afb3-3cf202672cc9
		$a_01_2 = {63 72 79 70 74 6c 6f 61 64 2e 65 78 65 } //1 cryptload.exe
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}