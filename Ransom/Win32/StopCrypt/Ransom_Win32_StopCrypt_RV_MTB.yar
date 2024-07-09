
rule Ransom_Win32_StopCrypt_RV_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 c0 ?? 89 45 ?? 83 6d ?? ?? 8a 4d ?? 30 0c 1e 83 ff ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}