
rule Ransom_Win32_StopCrypt_SLG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 01 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 54 24 ?? 83 3d ?? ?? ?? ?? 0c 89 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}