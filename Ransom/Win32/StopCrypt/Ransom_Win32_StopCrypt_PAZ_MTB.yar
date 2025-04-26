
rule Ransom_Win32_StopCrypt_PAZ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 31 4d ?? 8b 4d ?? d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 33 55 ?? 89 55 ?? 3d a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}