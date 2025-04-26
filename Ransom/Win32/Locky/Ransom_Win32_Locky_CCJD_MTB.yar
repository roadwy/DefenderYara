
rule Ransom_Win32_Locky_CCJD_MTB{
	meta:
		description = "Ransom:Win32/Locky.CCJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 a5 78 ff ff ff 00 c7 45 84 b2 c5 1f e6 c7 45 88 97 17 52 9a c7 85 70 ff ff ff 54 c8 30 e5 c7 85 7c ff ff ff 54 c8 30 e5 c7 45 80 26 d3 74 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}