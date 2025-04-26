
rule Trojan_Win32_Graftor_MKV_MTB{
	meta:
		description = "Trojan:Win32/Graftor.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 ca 0f b6 c9 02 c1 0f b6 c0 8d 44 83 04 8a 08 30 0f 8b 08 8b 85 ?? ?? ?? ?? 31 08 8b 0e 03 8d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 31 08 ff 85 ?? ?? fe ff 81 bd ?? ?? fe ff 38 3d 49 00 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}