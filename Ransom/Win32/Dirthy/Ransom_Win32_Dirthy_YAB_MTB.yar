
rule Ransom_Win32_Dirthy_YAB_MTB{
	meta:
		description = "Ransom:Win32/Dirthy.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d e4 89 4d d8 8b 55 d8 0f be 02 35 aa 00 00 00 8b 4d d8 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}