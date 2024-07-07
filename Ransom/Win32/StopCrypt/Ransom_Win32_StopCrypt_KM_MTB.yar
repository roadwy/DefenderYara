
rule Ransom_Win32_StopCrypt_KM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 84 0d 44 90 02 03 4a 32 03 41 88 07 43 47 3b ce 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}