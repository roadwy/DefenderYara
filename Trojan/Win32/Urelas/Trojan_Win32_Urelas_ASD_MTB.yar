
rule Trojan_Win32_Urelas_ASD_MTB{
	meta:
		description = "Trojan:Win32/Urelas.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 f8 05 8b 04 85 [0-03] 00 8b fa 83 e7 1f c1 e7 06 8b 04 07 83 f8 ff 74 08 3b c6 74 04 85 c0 75 02 89 31 83 c1 20 42 81 f9 38 22 42 00 7c } //2
		$a_01_1 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //1 golfinfo.ini
		$a_01_2 = {47 00 44 00 53 00 47 00 44 00 57 00 48 00 53 00 59 00 44 00 } //1 GDSGDWHSYD
		$a_01_3 = {42 00 6f 00 61 00 68 00 6b 00 69 00 6c 00 73 00 65 00 72 00 } //1 Boahkilser
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}