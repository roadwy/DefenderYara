
rule Trojan_Win32_CobaltStrike_LKQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b 55 0c 7d 0e 89 d1 83 e1 07 8a 0c 08 30 0c 13 42 eb ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}