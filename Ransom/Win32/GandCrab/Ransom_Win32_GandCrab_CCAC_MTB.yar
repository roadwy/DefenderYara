
rule Ransom_Win32_GandCrab_CCAC_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.CCAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 03 01 8b 55 f8 03 55 f0 33 c2 8b 4d f8 c1 e9 ?? 8b 55 0c 03 4a 04 33 c1 8b 4d e4 2b c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}