
rule Trojan_BAT_NJRat_ARA_MTB{
	meta:
		description = "Trojan:BAT/NJRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 02 09 11 04 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 13 05 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 00 06 09 11 04 17 58 9a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 00 11 04 18 58 13 04 11 04 09 28 ?? ?? ?? 2b 17 59 fe 04 13 07 11 07 2d af } //2
		$a_01_1 = {5c 6f 62 6a 5c 44 65 62 75 67 5c 53 74 75 62 42 69 6e 64 65 72 2e 70 64 62 } //2 \obj\Debug\StubBinder.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_NJRat_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/NJRat.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 30 37 64 63 64 62 30 63 2d 66 66 64 37 2d 34 62 62 32 2d 61 65 31 65 2d 33 37 36 30 63 65 37 63 66 63 61 32 } //2 $07dcdb0c-ffd7-4bb2-ae1e-3760ce7cfca2
		$a_01_1 = {5c 42 69 6e 64 65 72 20 42 79 20 4f 78 20 6d 75 68 61 6d 6d 65 64 5c 73 74 75 62 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62 } //2 \Binder By Ox muhammed\stub\obj\x86\Release\stub.pdb
		$a_01_2 = {73 74 75 62 2e 65 78 65 } //2 stub.exe
		$a_01_3 = {73 74 75 62 2e 52 65 73 6f 75 72 63 65 73 } //2 stub.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}