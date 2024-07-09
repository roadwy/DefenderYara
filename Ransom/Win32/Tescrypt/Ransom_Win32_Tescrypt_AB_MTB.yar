
rule Ransom_Win32_Tescrypt_AB_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 0f 88 4c 24 ?? 8b 54 24 ?? 8b 7c 24 ?? 8a 4c 24 ?? 80 f1 ?? 88 4c 24 ?? 0f be 4c 24 1f 0f be 14 3a 29 ca 88 d1 88 4c 24 ?? 8b 54 24 ?? 8a 4c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8b 7c 24 ?? 88 0c 17 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}