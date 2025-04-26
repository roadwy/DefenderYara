
rule Trojan_Win32_Duzse_A{
	meta:
		description = "Trojan:Win32/Duzse.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2a 00 56 00 49 00 52 00 54 00 55 00 41 00 4c 00 2a 00 } //1 *VIRTUAL*
		$a_01_1 = {2a 00 56 00 42 00 4f 00 58 00 2a 00 } //1 *VBOX*
		$a_03_2 = {8b 45 e4 03 85 ?? ff ff ff 0f 80 7c 01 00 00 89 45 e4 8b 45 e4 3b 85 ?? ff ff ff 0f 8f ad 00 00 00 8b 45 e8 89 85 ?? ff ff ff c7 85 ?? ff ff ff 08 00 00 00 c7 45 d8 01 00 00 00 c7 45 d0 02 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}