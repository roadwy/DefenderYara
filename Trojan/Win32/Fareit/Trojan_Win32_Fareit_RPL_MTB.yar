
rule Trojan_Win32_Fareit_RPL_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc e9 eb ff ff ff cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}