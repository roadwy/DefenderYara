
rule Trojan_Win32_Tofsee_WMK_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.WMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 03 d3 e8 03 45 ?? 33 c2 31 45 fc 8b 45 fc 29 45 f0 81 c3 47 86 c8 61 ff 4d e4 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}