
rule Ransom_Win32_GandCrab_EAXY_MTB{
	meta:
		description = "Ransom:Win32/GandCrab.EAXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 01 32 c2 02 c2 88 01 8d 49 01 4e } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}