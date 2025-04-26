
rule Trojan_Win32_Emotet_DCQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 04 29 8a 54 24 ?? 8a c8 f6 d1 f6 d2 0a d1 8a 4c 24 ?? 0a c8 8b 44 24 ?? 22 d1 88 14 28 8b 44 24 [0-04] 45 3b e8 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}