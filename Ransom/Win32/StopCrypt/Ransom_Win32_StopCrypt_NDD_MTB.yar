
rule Ransom_Win32_StopCrypt_NDD_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.NDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ee 8b 4c 24 30 8d 44 24 20 89 54 24 34 89 74 24 20 c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 34 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 60 10 40 00 8b 44 24 10 31 44 24 20 81 3d ?? ?? ?? ?? 13 02 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}