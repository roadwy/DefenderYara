
rule Ransom_Win32_StopCrypt_SW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}