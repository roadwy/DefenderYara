
rule Trojan_Win32_Ekstak_G_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 45 ec 89 45 ?? 53 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 c1 a9 ?? ?? ?? ?? e9 90 09 0b 00 a1 ?? ?? ?? ?? 33 05 } //1
		$a_02_1 = {8b 45 08 8b 00 a3 ?? ?? ?? ?? 3b 45 ?? 0f 95 c1 53 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 c1 a9 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Ekstak_G_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.G!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 57 57 ff 15 54 83 50 00 01 05 70 d9 50 00 68 48 a1 50 00 8d 55 dc 52 ff 15 64 d9 50 00 89 7d fc } //1
		$a_01_1 = {c7 05 a4 dc 50 00 50 72 6f 63 c7 05 a8 dc 50 00 65 73 73 33 c7 05 ac dc 50 00 32 46 69 72 66 c7 05 b0 dc 50 00 73 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}