
rule Trojan_Win32_Lotok_NK_MTB{
	meta:
		description = "Trojan:Win32/Lotok.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 38 2e 31 38 31 2e 32 32 2e 35 34 } //2 38.181.22.54
		$a_01_1 = {42 73 6a 62 73 2e 65 78 65 } //2 Bsjbs.exe
		$a_01_2 = {46 77 6e 66 77 6e 66 76 20 4f 67 77 6f 66 77 6f 66 77 20 4f 67 78 6f 67 77 6f 20 48 78 70 67 78 70 67 78 20 50 68 79 } //1 Fwnfwnfv Ogwofwofw Ogxogwo Hxpgxpgx Phy
		$a_01_3 = {41 71 69 79 71 69 20 41 72 69 61 72 69 61 71 20 4a 62 72 6a 61 72 6a 61 20 53 6a 62 73 } //1 Aqiyqi Ariariaq Jbrjarja Sjbs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}