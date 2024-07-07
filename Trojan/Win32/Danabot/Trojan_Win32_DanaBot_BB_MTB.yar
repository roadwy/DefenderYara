
rule Trojan_Win32_DanaBot_BB_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 d3 e6 8b c8 c1 e9 90 01 01 03 4d 90 01 01 03 75 90 01 01 89 15 90 01 04 33 f1 8b 4d 90 01 01 03 c8 33 f1 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}