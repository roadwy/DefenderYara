
rule Ransom_Win32_Mole_DA_MTB{
	meta:
		description = "Ransom:Win32/Mole.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 8b 4d f0 03 02 31 4d d8 33 02 50 8f 03 83 c2 04 0f b6 c1 8b c1 0b 05 ?? ?? ?? ?? 47 8b c7 89 7d e0 8b 7d 18 2b c7 8b 7d e0 75 6b } //1
		$a_03_1 = {33 c9 81 e9 52 15 48 10 8b 0d ?? ?? ?? ?? 03 35 ?? ?? ?? ?? f7 5d d8 83 c3 04 49 0f 85 90 09 06 00 89 0d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}