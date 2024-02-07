
rule Trojan_Win32_Floganix_A{
	meta:
		description = "Trojan:Win32/Floganix.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {ff 4d f8 4b 47 80 3b 72 75 3a 56 89 5d fc ff 15 90 01 04 83 65 f4 00 85 c0 89 45 f0 76 1f 8b cb 0f be 04 0f 0f b6 11 3b c2 75 0e 90 00 } //01 00 
		$a_01_1 = {43 46 6f 78 67 6c 69 6e 61 4d 6f 64 75 6c 65 } //01 00  CFoxglinaModule
		$a_01_2 = {66 6f 78 67 6c 69 6e 61 2e 64 6c 6c 00 4e 53 47 65 74 4d 6f 64 75 6c 65 } //01 00  潦杸楬慮搮汬一䝓瑥潍畤敬
		$a_01_3 = {66 69 72 65 68 66 78 74 69 65 7a } //00 00  firehfxtiez
	condition:
		any of ($a_*)
 
}