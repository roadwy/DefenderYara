
rule Ransom_Win32_CobaltStrike_MTB{
	meta:
		description = "Ransom:Win32/CobaltStrike!MTB,SIGNATURE_TYPE_PEHSTR,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 c7 45 e0 9c 00 00 00 48 8d 05 f4 d9 02 00 48 89 45 e8 48 8b 45 18 8b 10 48 8b 45 10 83 e0 1f 41 b8 01 00 00 00 89 c1 49 d3 e0 4c 89 c0 09 c2 } //1
		$a_01_1 = {48 c7 45 d0 5b 01 00 00 48 8d 05 47 dd 02 00 48 89 45 d8 48 8b 45 20 25 ff 01 00 00 48 89 45 f0 48 c7 45 d0 5c 01 00 00 48 8d 05 27 dd 02 00 } //2
		$a_01_2 = {48 83 c2 02 4c 8b 04 d0 48 8b 45 f0 83 e0 3f ba 01 00 00 00 89 c1 48 d3 e2 48 89 d1 48 8b 45 f0 48 c1 f8 06 48 89 c2 4c 09 c1 48 8b 45 f8 48 83 c2 02 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}