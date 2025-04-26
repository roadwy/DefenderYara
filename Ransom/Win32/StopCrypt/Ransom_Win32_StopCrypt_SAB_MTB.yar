
rule Ransom_Win32_StopCrypt_SAB_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 25 ?? ?? ?? ?? ?? 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}