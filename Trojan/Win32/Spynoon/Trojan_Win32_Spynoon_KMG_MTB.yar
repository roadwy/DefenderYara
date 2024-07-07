
rule Trojan_Win32_Spynoon_KMG_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {24 0f 85 f6 75 90 01 01 c0 e0 04 be 01 00 00 00 88 01 eb 90 01 01 08 01 33 f6 41 42 3b 90 01 01 72 90 09 0a 00 8a 82 90 01 04 84 c0 74 90 00 } //1
		$a_02_1 = {24 0f 85 c9 75 90 01 01 c0 e0 04 b9 01 00 00 00 88 02 eb 90 01 01 08 02 33 c9 42 46 3b f7 72 90 09 0a 00 8a 86 90 01 04 84 c0 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}