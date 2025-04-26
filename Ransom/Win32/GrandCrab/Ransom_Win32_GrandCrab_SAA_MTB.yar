
rule Ransom_Win32_GrandCrab_SAA_MTB{
	meta:
		description = "Ransom:Win32/GrandCrab.SAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 1e 2b 75 e8 33 c8 2b f9 83 6d fc 01 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}