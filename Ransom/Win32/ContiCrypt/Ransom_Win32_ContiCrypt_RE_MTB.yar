
rule Ransom_Win32_ContiCrypt_RE_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 90 88 07 90 46 90 47 90 49 83 f9 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}