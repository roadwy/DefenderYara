
rule Ransom_Win32_StopCrypt_SLA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e0 90 01 01 03 45 90 01 01 8d 0c 16 33 c1 89 4d 90 01 01 8b ca c1 e9 90 01 01 03 4d 90 01 01 89 45 90 01 01 33 c8 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 8b 45 90 01 01 29 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}