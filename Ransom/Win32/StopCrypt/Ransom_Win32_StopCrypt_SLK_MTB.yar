
rule Ransom_Win32_StopCrypt_SLK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e9 90 01 01 03 4d 90 01 01 8b d6 c1 e2 90 01 01 03 55 90 01 01 03 c6 33 ca 33 c8 89 45 90 01 01 89 4d 0c 8b 45 0c 01 05 90 01 04 8b 45 0c 29 45 90 01 01 8b 45 90 01 01 c1 e0 90 01 01 03 c3 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}