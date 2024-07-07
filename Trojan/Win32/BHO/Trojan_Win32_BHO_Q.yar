
rule Trojan_Win32_BHO_Q{
	meta:
		description = "Trojan:Win32/BHO.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 0c 56 8b 74 24 0c 33 c9 85 f6 89 30 8b 44 24 08 7e 34 57 eb 08 8d a4 24 00 00 00 00 90 8a 14 01 0f be fa 81 e7 03 00 00 80 79 05 4f 83 cf fc 47 74 03 80 c2 fc 88 14 01 83 c1 01 3b ce 7c de 5f c6 04 30 00 5e c3 } //1
		$a_01_1 = {7b 6d 72 64 73 7b 32 73 72 69 76 76 73 76 41 6a 79 72 67 74 6d 73 72 28 2d } //1 {mrds{2srivvsvAjyrgtmsr(-
		$a_01_2 = {57 73 6a 74 7b 65 76 69 5c 51 6d 67 76 73 77 73 6a 74 5c 4d 72 74 69 76 72 69 74 20 49 78 70 6c 73 76 69 76 5c 52 69 7b 20 5b 6d 72 64 73 7b 77 5c 45 6c 6c 73 7b } //1 Wsjt{evi\Qmgvswsjt\Mrtivrit Ixplsviv\Ri{ [mrds{w\Ells{
		$a_01_3 = {77 68 69 6c 6c 37 36 32 64 6c 6c } //1 whill762dll
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}