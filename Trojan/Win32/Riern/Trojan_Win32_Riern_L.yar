
rule Trojan_Win32_Riern_L{
	meta:
		description = "Trojan:Win32/Riern.L,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 69 64 65 62 61 72 2e 65 78 65 00 73 } //10
		$a_02_1 = {8b b4 bc 18 01 00 00 3b f5 0f 84 ?? 00 00 00 68 04 01 00 00 8d 44 24 18 6a 00 50 e8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b [0-05] 83 c4 0c 56 6a 00 68 10 04 00 00 ff d2 } //10
		$a_02_2 = {8b 5f 14 03 da 3b d9 76 20 83 [0-02] 10 72 02 8b 00 } //1
		$a_00_3 = {8b 5e 14 03 da 3b d9 76 19 83 ff 10 72 02 8b 00 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}