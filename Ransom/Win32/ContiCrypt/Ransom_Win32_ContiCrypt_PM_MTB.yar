
rule Ransom_Win32_ContiCrypt_PM_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 73 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 8b 45 ?? 33 d2 be 0f 00 00 00 f7 f6 33 4c 95 ?? 8b 55 ?? 03 55 ?? 88 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}