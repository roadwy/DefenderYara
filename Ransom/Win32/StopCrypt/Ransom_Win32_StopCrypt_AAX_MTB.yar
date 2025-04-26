
rule Ransom_Win32_StopCrypt_AAX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.AAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 cc 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 4d fc 89 45 f8 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}