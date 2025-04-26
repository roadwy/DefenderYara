
rule Trojan_Win32_Emotet_DCG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d5 8b c6 33 d2 b9 ?? ?? ?? ?? f7 f1 8a 04 3e 8a 14 53 32 c2 88 04 3e 8b 44 24 [0-04] 3b f0 75 } //1
		$a_02_1 = {6a 00 ff 15 38 c6 40 00 8b 44 24 ?? 6a ?? 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 ?? 8a 04 50 30 01 [0-03] 3b 74 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}