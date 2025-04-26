
rule Trojan_WinNT_Alureon_F{
	meta:
		description = "Trojan:WinNT/Alureon.F,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {87 1c 24 87 4c 24 04 87 54 24 08 87 6c 24 0c 56 57 55 52 51 53 c3 } //1
		$a_02_1 = {0f b7 81 06 02 00 00 81 e9 ?? fe ff ff 81 } //1
		$a_02_2 = {25 00 f0 ff ff 66 81 38 4d 5a 0f 84 ?? 00 00 00 } //1
		$a_02_3 = {68 a2 b3 45 5e ff 75 ?? e8 } //1
		$a_00_4 = {68 61 6c 2e 64 6c 6c 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}