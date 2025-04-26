
rule Ransom_Win32_StopCrypt_MOK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 [0-01] c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}