
rule Trojan_Win32_CobaltStrike_PA_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 d2 83 ec ?? 39 da 7d ?? 89 d1 8b 75 10 83 e1 03 8a 0c 0e 8b 75 08 32 0c 16 88 0c 10 42 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_CobaltStrike_PA_MTB_2{
	meta:
		description = "Trojan:Win32/CobaltStrike.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff c0 89 85 ?? ?? 00 00 8b 45 04 39 85 ?? ?? 00 00 7d 22 48 63 85 ?? ?? 00 00 0f b6 84 05 ?? 00 00 00 83 f0 0a 48 63 8d ?? ?? 00 00 88 84 0d ?? 00 00 00 eb } //1
		$a_00_1 = {5c 63 6f 62 61 6c 74 73 74 72 69 6b 65 20 33 2e 31 34 5c 70 61 79 6c 6f 61 64 5c 41 76 42 79 50 61 73 73 } //1 \cobaltstrike 3.14\payload\AvByPass
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}