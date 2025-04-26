
rule Ransom_Win32_TeslaCrypt_NM_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 ea 89 44 24 ?? 88 4c 24 2f 0f 87 ?? ?? ?? ?? e9 a6 00 00 00 8b 44 24 } //3
		$a_03_1 = {58 89 44 24 ?? e9 f6 00 00 00 8a 84 24 ?? ?? ?? ?? 34 b6 8b 4c 24 4c 8a 54 24 ?? 83 c1 01 89 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}