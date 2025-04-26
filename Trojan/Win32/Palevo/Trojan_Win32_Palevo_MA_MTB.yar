
rule Trojan_Win32_Palevo_MA_MTB{
	meta:
		description = "Trojan:Win32/Palevo.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 10 46 38 9e 90 0a 13 00 8b 81 ?? ?? ?? ?? 8a 96 [0-0f] 0f 44 f3 38 18 74 ?? 40 eb ?? 83 c1 04 83 f9 74 72 } //1
		$a_03_1 = {66 0f b6 d2 66 8b c1 66 0b c2 66 89 07 74 ?? 47 47 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}