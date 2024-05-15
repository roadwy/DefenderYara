
rule Trojan_Win32_Ursnif_GXY_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b cf 8b c7 c1 e9 90 01 01 03 4d 90 01 01 c1 e0 90 01 01 03 45 90 01 01 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 90 01 01 03 4d 90 01 01 c1 e0 90 01 01 03 45 90 01 01 33 c8 8d 04 1e 33 c8 8d b6 47 86 c8 61 2b f9 ff 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}