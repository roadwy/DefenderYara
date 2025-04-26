
rule Trojan_Win32_Dridex_ZV{
	meta:
		description = "Trojan:Win32/Dridex.ZV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 53 8b 00 3d fd 00 00 c0 77 14 74 ?? 3d 03 00 00 80 0f 84 6a 05 00 00 3d 05 00 00 c0 eb 05 3d 74 03 00 c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}