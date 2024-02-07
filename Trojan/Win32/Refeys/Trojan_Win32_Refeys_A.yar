
rule Trojan_Win32_Refeys_A{
	meta:
		description = "Trojan:Win32/Refeys.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 63 6f 6d 6d 61 6e 64 3d 6b 6e 6f 63 6b 26 75 73 65 72 6e 61 6d 65 3d } //01 00  &command=knock&username=
		$a_03_1 = {8b 43 0c 8b 00 8b 00 68 90 01 04 ff 37 89 45 90 01 01 ff d6 85 c0 74 90 01 01 6a 50 ff d0 68 90 01 04 ff 37 66 89 45 90 01 01 ff d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}