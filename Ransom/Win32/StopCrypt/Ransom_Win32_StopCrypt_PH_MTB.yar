
rule Ransom_Win32_StopCrypt_PH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 04 33 44 24 08 c2 08 00 81 00 fe 36 ef c6 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}