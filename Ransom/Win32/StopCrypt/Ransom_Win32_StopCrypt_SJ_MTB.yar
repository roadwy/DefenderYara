
rule Ransom_Win32_StopCrypt_SJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 90 01 01 8d 0c 1f 33 c8 89 45 90 01 01 89 4d 90 01 01 89 35 90 01 04 8b 45 90 01 01 01 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}