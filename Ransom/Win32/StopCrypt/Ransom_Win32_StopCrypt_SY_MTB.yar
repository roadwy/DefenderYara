
rule Ransom_Win32_StopCrypt_SY_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 3d 90 01 04 03 55 90 01 01 33 55 90 01 01 33 d6 89 55 90 01 01 8b 45 90 01 01 29 45 90 01 01 8d 45 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}