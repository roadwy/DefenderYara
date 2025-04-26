
rule Trojan_Win32_QBot_RPW_MTB{
	meta:
		description = "Trojan:Win32/QBot.RPW!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 52 50 a1 b4 0e 47 00 33 d2 3b 54 24 04 75 0d 3b 04 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}