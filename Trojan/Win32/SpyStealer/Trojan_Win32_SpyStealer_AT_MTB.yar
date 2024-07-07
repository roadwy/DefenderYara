
rule Trojan_Win32_SpyStealer_AT_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 04 00 00 00 f7 f1 a1 90 02 04 0f be 0c 10 8b 55 ec 0f b6 82 90 02 04 33 c1 8b 4d ec 88 81 90 02 04 eb c2 90 00 } //2
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}