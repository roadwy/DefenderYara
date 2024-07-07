
rule Trojan_Win32_Emotet_CR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 44 03 d5 03 d3 8a 14 02 8b 44 24 3c 30 14 38 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}