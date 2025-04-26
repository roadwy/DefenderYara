
rule Trojan_Win32_CobaltStrike_GCD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 d9 89 c7 89 85 ?? ?? ?? ?? 31 c0 f3 a4 39 c3 74 ?? 8b 95 ?? ?? ?? ?? 80 34 02 03 40 eb } //10
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}