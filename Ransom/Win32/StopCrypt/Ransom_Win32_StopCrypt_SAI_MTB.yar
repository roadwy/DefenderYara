
rule Ransom_Win32_StopCrypt_SAI_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 83 0d 90 01 05 8b c6 c1 e8 90 01 01 03 45 90 01 01 03 ce 33 c8 31 4d 90 01 01 2b 7d 90 01 01 c7 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}