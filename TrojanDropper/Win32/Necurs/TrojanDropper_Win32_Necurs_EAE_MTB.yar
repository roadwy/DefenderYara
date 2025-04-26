
rule TrojanDropper_Win32_Necurs_EAE_MTB{
	meta:
		description = "TrojanDropper:Win32/Necurs.EAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4d a4 c1 45 a4 0b 8b 55 a4 33 15 ?? ?? ?? ?? 89 55 a4 8b 45 e8 8b 4d f8 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}