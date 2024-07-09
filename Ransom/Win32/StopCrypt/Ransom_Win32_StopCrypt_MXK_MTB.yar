
rule Ransom_Win32_StopCrypt_MXK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 05 [0-04] 89 01 c3 [0-05] 01 08 c3 [0-0d] 31 08 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}