
rule Ransom_Win32_StopCrypt_MCC_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea ?? 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef ?? 8b 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}