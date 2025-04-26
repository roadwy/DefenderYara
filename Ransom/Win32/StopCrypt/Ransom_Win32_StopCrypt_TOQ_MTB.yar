
rule Ransom_Win32_StopCrypt_TOQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.TOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 70 8b 45 70 03 85 14 ff ff ff 8d 14 33 33 c2 33 c1 2b f8 8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b 85 10 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}