
rule Ransom_Win32_DharmaCrypt_YAB_MTB{
	meta:
		description = "Ransom:Win32/DharmaCrypt.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 2b 45 ?? 8b 1d ?? ?? ?? ?? 0f af c7 0f af 45 ?? 03 c1 8a d0 32 55 ?? 88 54 1d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}