
rule Trojan_Win32_Emotet_PDT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d ?? 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d } //1
		$a_81_1 = {54 4b 32 59 50 4c 71 38 6b 7a 39 56 6d 78 65 77 42 6a 79 39 72 4b 78 53 51 66 67 50 59 42 74 6e 73 51 79 31 51 58 } //1 TK2YPLq8kz9VmxewBjy9rKxSQfgPYBtnsQy1QX
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}