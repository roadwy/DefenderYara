
rule Trojan_Win32_LummaStealer_POV_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.POV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b 45 0c 66 8b 00 0f bf 55 ?? 89 14 24 0f b7 c0 89 44 24 04 ?? fe 05 00 00 83 ec 08 34 ff 88 45 f3 8a 45 f3 a8 01 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}