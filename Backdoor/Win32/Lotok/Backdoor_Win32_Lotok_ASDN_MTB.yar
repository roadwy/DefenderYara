
rule Backdoor_Win32_Lotok_ASDN_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.ASDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 31 80 c2 03 32 da 47 88 1c 31 b9 05 00 00 00 99 f7 f9 89 7d e8 85 d2 75 } //2
		$a_03_1 = {8b 4d e4 6a 04 68 00 20 00 00 8b 51 50 52 56 ff 15 ?? ?? ?? 00 3b c6 89 45 ec } //1
		$a_01_2 = {46 77 6e 66 77 6e 66 76 20 4f 67 77 6f 66 77 6f 66 77 20 4f 67 78 6f 67 77 6f 20 48 78 70 67 78 70 67 78 20 50 68 79 } //1 Fwnfwnfv Ogwofwofw Ogxogwo Hxpgxpgx Phy
		$a_01_3 = {41 71 69 79 71 69 20 41 72 69 61 72 69 61 71 20 4a 62 72 6a 61 72 6a 61 20 53 6a 62 73 } //1 Aqiyqi Ariariaq Jbrjarja Sjbs
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}