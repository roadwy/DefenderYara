
rule Trojan_Win32_ShipUp_DSK_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 8b 02 33 45 ?? 8b 4d f8 89 01 c7 45 ?? 8e c3 66 00 8b e5 5d c3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}