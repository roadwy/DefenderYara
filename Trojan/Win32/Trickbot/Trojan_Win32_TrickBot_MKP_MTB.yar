
rule Trojan_Win32_TrickBot_MKP_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.MKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 58 8d 7c 24 03 8d 74 24 43 8b df 03 ea 3b de 0f 43 df 8a 0b 43 30 0a 42 3b d5 72 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}