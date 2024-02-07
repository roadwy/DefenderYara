
rule Trojan_Win32_Krypter_AB_MTB{
	meta:
		description = "Trojan:Win32/Krypter.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {5f 89 30 5e 5b c9 c2 90 0a 2f 00 2b 75 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 01 04 8b 45 90 01 01 89 78 90 00 } //01 00 
		$a_01_1 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //01 00  LocalAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}