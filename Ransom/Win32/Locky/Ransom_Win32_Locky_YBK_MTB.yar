
rule Ransom_Win32_Locky_YBK_MTB{
	meta:
		description = "Ransom:Win32/Locky.YBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 2f 8a 16 31 f6 30 d5 88 2f 8b 5c 24 04 83 c3 02 89 5c 24 04 8b 1c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}