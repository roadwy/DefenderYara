
rule Trojan_Win32_Netwire_ZV_MTB{
	meta:
		description = "Trojan:Win32/Netwire.ZV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c0 83 f6 00 83 f6 00 ad 83 f6 00 66 3d 6e 36 85 c0 66 3d 4c 41 85 c0 85 c0 66 83 f8 28 8b 1c 0f 66 3d d1 2f 85 c0 83 f6 00 83 f6 00 66 3d a6 bb 83 f6 00 66 3d 8d a0 85 c0 83 f6 00 85 c0 31 c3 } //00 00 
	condition:
		any of ($a_*)
 
}