
rule Ransom_Win32_StopCrypt_PM_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c2 04 00 c1 e0 04 89 01 c3 83 3d ?? ?? ?? ?? 7e } //1
		$a_03_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 12 37 ef c6 c3 01 08 c3 29 08 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}