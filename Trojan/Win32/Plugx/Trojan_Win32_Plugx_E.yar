
rule Trojan_Win32_Plugx_E{
	meta:
		description = "Trojan:Win32/Plugx.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {31 c0 31 db 8a 04 11 b3 ?? 28 d8 30 d8 00 d8 88 04 11 83 f9 00 74 03 49 eb e6 } //1
		$a_01_1 = {68 2e 68 6c 70 54 } //1 h.hlpT
		$a_03_2 = {c6 00 68 c7 40 01 ff ff ff ff c6 40 05 68 c7 40 06 ?? ?? ?? ?? c6 40 0a c3 } //1
		$a_01_3 = {3c 00 74 09 38 d0 74 05 30 d0 88 04 0b 83 f9 00 74 03 49 eb e6 } //1
		$a_03_4 = {8b 45 f8 ff d0 6a ff e8 ?? ?? ?? ?? 6a ff e8 ?? ?? ?? ?? 6a ff e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}