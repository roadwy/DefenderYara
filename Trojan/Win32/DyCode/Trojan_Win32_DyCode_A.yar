
rule Trojan_Win32_DyCode_A{
	meta:
		description = "Trojan:Win32/DyCode.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {bd 4b 48 43 42 66 b8 04 00 [0-02] cc } //2
		$a_03_1 = {50 6a 40 8b 45 ?? 50 8b 45 fc 50 ff 15 ?? ?? ?? ?? 8b 45 fc ff d0 } //1
		$a_03_2 = {c6 03 c3 e8 ?? ?? ?? ?? 5a 5b c3 } //1
		$a_03_3 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d ?? ?? ?? ?? 88 c3 32 de c1 e8 08 33 04 9d ?? ?? ?? ?? c1 ea 10 } //1
		$a_00_4 = {53 48 45 4c 4c 00 00 00 43 4f 44 45 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}