
rule Ransom_Win32_DithyRamb_A_MTB{
	meta:
		description = "Ransom:Win32/DithyRamb.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 89 4d fc 0f be 45 08 35 aa 00 00 00 8b e5 5d c2 04 00 } //1
		$a_01_1 = {8b 45 e4 3b 45 d0 74 18 8b 4d e4 89 4d d8 8b 55 d8 0f be 02 35 aa 00 00 00 8b 4d d8 88 01 } //1
		$a_01_2 = {8b 55 fc 3b 55 f0 74 19 8b 45 fc 89 45 f4 8b 4d f4 0f be 11 81 f2 aa 00 00 00 8b 45 f4 88 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}