
rule Trojan_WinNT_Whycan_A{
	meta:
		description = "Trojan:WinNT/Whycan.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {81 e9 00 20 22 00 0f ?? ?? ?? ?? ?? 83 e9 05 74 ?? 83 e9 06 74 ?? c7 45 d4 32 02 00 c0 } //1
		$a_02_1 = {8b 7b 0c 85 ff 0f 84 ?? ?? ?? ?? 80 bf 8a 63 00 00 01 0f 85 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8d b7 a8 2a 00 00 } //1
		$a_02_2 = {8d 86 50 14 00 00 8b 4d ?? 8d 1c 31 8b d3 2b d0 0f b7 08 66 89 0c 02 } //1
		$a_02_3 = {8b f3 a5 66 a5 50 a4 e8 ?? ?? ?? ?? 33 c0 8b fb ab 66 ab 5e aa 5b } //1
		$a_00_4 = {0f b7 07 b9 6e 6b 00 00 66 3b c1 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}