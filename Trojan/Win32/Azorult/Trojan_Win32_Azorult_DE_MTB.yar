
rule Trojan_Win32_Azorult_DE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 33 d2 f7 75 f0 8a 04 32 30 04 19 41 3b cf 72 ee } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}