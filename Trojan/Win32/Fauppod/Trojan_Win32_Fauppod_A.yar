
rule Trojan_Win32_Fauppod_A{
	meta:
		description = "Trojan:Win32/Fauppod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {78 50 2b 3d 5f 2e 70 64 62 00 } //1
		$a_03_1 = {66 c7 00 4d 5a [0-03] c7 ?? 3c c0 00 00 00 c7 ?? c0 00 00 00 50 45 } //1
		$a_03_2 = {e8 de ff ff ff 40 90 0a 1a 00 89 18 89 f0 01 05 ?? ?? ?? ?? 89 ea 01 15 } //1
		$a_03_3 = {e8 df ff ff ff 40 90 0a 2a 00 e8 ?? ?? ?? ?? 89 d8 a3 ?? ?? ?? ?? 89 f0 31 05 ?? ?? ?? ?? 89 ea 01 15 } //1
		$a_01_4 = {8b 30 8b 78 04 8b 58 08 8b 68 0c 8b 60 10 8b 40 14 ff e0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}