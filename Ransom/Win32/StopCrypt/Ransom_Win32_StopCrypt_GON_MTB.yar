
rule Ransom_Win32_StopCrypt_GON_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.GON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea 05 03 54 24 20 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b f2 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}