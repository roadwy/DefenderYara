
rule Trojan_Win32_Dridex_DEQ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 d8 0f b7 d0 03 54 24 14 8b 0e 81 c1 ?? ?? ?? ?? 0f b7 c2 89 0e 05 ?? ?? ?? ?? 83 c6 04 83 6c 24 10 01 75 } //1
		$a_02_1 = {8b de 2b 5c 24 20 83 c3 05 8b 54 24 0c 8b c8 2b 4c 24 18 81 c2 ?? ?? ?? ?? 03 ce 89 54 24 0c 0f b7 c9 83 c6 27 81 7c 24 14 ?? ?? ?? ?? 89 4c 24 18 8b 4c 24 10 89 15 ?? ?? ?? ?? 89 11 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}