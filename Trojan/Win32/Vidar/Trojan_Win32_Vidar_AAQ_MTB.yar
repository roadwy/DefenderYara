
rule Trojan_Win32_Vidar_AAQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 90 01 01 8b 4d fc 8a 04 02 32 04 31 47 88 06 3b 7d 10 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}