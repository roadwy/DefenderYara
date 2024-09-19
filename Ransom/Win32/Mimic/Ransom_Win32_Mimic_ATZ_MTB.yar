
rule Ransom_Win32_Mimic_ATZ_MTB{
	meta:
		description = "Ransom:Win32/Mimic.ATZ!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 65 f8 00 0f af 05 d8 6e 5f 00 8d 4d f0 33 d2 c7 45 fc e8 9a 53 00 f7 f7 03 05 d8 6e 5f 00 50 } //1
		$a_01_1 = {8b 56 08 8b 45 08 c1 ea 03 c1 e8 03 2b d0 } //1
		$a_01_2 = {33 c0 40 f0 0f c1 41 14 40 83 f8 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}