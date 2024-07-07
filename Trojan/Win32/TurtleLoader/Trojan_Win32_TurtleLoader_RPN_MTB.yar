
rule Trojan_Win32_TurtleLoader_RPN_MTB{
	meta:
		description = "Trojan:Win32/TurtleLoader.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7d 1a 89 c8 99 f7 ff 8b 45 10 8a 04 10 8b 55 08 32 04 0a 88 04 0a 88 04 0b 41 eb e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}