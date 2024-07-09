
rule Trojan_Win32_Racealer_DEA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b d0 d3 e2 8b c8 c1 e9 05 03 8d ?? fd ff ff 03 95 ?? fd ff ff 03 f8 33 d1 33 d7 89 95 ?? fd ff ff 89 35 } //1
		$a_81_1 = {73 6c 6f 6b 61 64 6e 69 61 73 64 62 66 69 61 73 64 } //1 slokadniasdbfiasd
		$a_81_2 = {66 61 69 75 73 64 66 69 61 73 64 68 67 6f 73 64 66 6a 67 6f 73 } //1 faiusdfiasdhgosdfjgos
		$a_81_3 = {64 67 6f 73 64 66 6a 67 6f 69 73 64 6f 66 67 6d } //1 dgosdfjgoisdofgm
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}