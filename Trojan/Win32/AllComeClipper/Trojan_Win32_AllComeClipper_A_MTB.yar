
rule Trojan_Win32_AllComeClipper_A_MTB{
	meta:
		description = "Trojan:Win32/AllComeClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 57 8b 3d ?? 50 41 00 0f 1f 80 00 00 00 00 6a 2e ff d3 6a 12 66 8b f0 ff d3 6a 11 66 23 f0 ff d3 66 85 c6 0f ?? ?? 00 00 00 6a 00 6a 02 ff 15 ?? 50 41 00 8b f0 83 fe ff 0f ?? ?? 00 00 00 8d 44 24 38 c7 44 24 38 28 01 00 00 50 56 ff 15 ?? 50 41 00 85 c0 0f 84 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}