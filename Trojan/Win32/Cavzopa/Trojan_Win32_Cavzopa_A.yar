
rule Trojan_Win32_Cavzopa_A{
	meta:
		description = "Trojan:Win32/Cavzopa.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 04 8d 04 80 83 c0 64 50 6b c3 1e 83 c0 64 50 e8 ?? ?? ?? ?? 6a 0a e8 ?? ?? ?? ?? 43 83 fb 1a 75 db } //1
		$a_03_1 = {ba 58 02 00 00 b8 20 03 00 00 e8 ?? ?? ?? ?? eb } //1
		$a_03_2 = {8b 43 0c 50 33 c0 8a 43 04 0f be 53 06 8d 14 52 8d 14 d5 ?? ?? ?? ?? 8b 04 82 50 e8 ?? ?? ?? ?? 8b 43 08 50 e8 ?? ?? ?? ?? 83 7d fc 00 75 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}