
rule Ransom_Win32_Eterniity_YAQ_MTB{
	meta:
		description = "Ransom:Win32/Eterniity.YAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 f1 8b 45 ec 0f be 0c 10 8b 55 e0 0f be 04 16 33 c1 8b 4d f8 8b 51 78 8b 4d e0 88 04 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}