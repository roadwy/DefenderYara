
rule Ransom_Win32_ContiCrypt_PM_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 90 01 01 8b 4d 90 01 01 3b 4d 90 01 01 73 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 0a 8b 45 90 01 01 33 d2 be 0f 00 00 00 f7 f6 33 4c 95 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 0a eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}