
rule Trojan_Win32_Tofsee_TTW_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.TTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 74 8b 45 74 03 85 14 ff ff ff 8b 95 38 ff ff ff 03 d6 33 c2 33 c1 2b f8 83 3d ?? ?? ?? ?? 0c c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 74 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}