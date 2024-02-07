
rule Trojan_Win32_Yangxiay_A_sys{
	meta:
		description = "Trojan:Win32/Yangxiay.A!sys,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {bb 10 00 00 c0 8b 75 0c 8b 46 60 8b 48 0c 8b 50 10 89 55 e4 8b 7e 3c 8b 40 04 89 45 d4 81 f9 4b e1 22 00 0f 85 90 01 01 00 00 00 83 65 fc 00 6a 04 5b 53 53 52 ff 90 01 03 01 00 90 00 } //01 00 
		$a_00_1 = {44 69 73 50 61 74 63 68 43 72 65 61 74 65 21 } //01 00  DisPatchCreate!
		$a_00_2 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //00 00  KeServiceDescriptorTable
	condition:
		any of ($a_*)
 
}