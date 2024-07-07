
rule Trojan_Win32_RacoonStealer_AZ_MTB{
	meta:
		description = "Trojan:Win32/RacoonStealer.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 08 89 38 5f 5e 89 50 04 5b c9 c2 04 00 90 0a 28 00 2b 7d 90 01 01 89 35 90 01 04 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 01 04 8b 90 00 } //1
		$a_01_1 = {4c 6f 63 61 6c 41 6c 6c 6f 63 } //1 LocalAlloc
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}