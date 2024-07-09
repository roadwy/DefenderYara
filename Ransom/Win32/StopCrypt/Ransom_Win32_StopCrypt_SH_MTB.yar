
rule Ransom_Win32_StopCrypt_SH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 3c 01 44 24 ?? 8b 54 24 ?? 33 54 24 ?? 8b 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 33 c2 2b f0 83 eb ?? 89 44 24 ?? 89 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}