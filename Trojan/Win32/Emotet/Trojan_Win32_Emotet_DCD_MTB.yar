
rule Trojan_Win32_Emotet_DCD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 d8 8b 4d d0 83 c0 01 89 0c 24 89 44 24 04 89 4d cc 89 45 c8 e8 90 01 04 8b 4d e8 8b 55 cc 8a 1c 11 80 c3 ff 2a 1c 05 90 01 04 8b 45 e4 88 1c 10 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}