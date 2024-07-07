
rule Ransom_Win32_Locky_ALK_MTB{
	meta:
		description = "Ransom:Win32/Locky.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 6d 00 8a 0e 31 f6 31 f6 31 f6 30 cd 30 cd 30 cd 88 6d 00 8b 1c 24 43 89 1c 24 8b 1c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}