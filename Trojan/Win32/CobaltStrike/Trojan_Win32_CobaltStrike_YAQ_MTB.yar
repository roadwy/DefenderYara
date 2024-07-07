
rule Trojan_Win32_CobaltStrike_YAQ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b 4d 10 73 13 89 c8 31 d2 8b 3b f7 f6 01 cf 41 8a 44 13 0c 30 07 eb e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}