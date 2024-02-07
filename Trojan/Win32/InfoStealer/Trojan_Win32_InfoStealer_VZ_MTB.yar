
rule Trojan_Win32_InfoStealer_VZ_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {d4 fe ff ff 83 c0 90 01 01 89 85 90 01 04 8b 8d 90 01 04 3b 4d 0c 73 22 0f b6 15 90 01 04 8b 45 08 03 85 90 01 04 0f b6 08 2b ca 8b 55 08 03 95 90 01 04 88 0a eb c4 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_2 = {2e 70 64 62 } //00 00  .pdb
	condition:
		any of ($a_*)
 
}