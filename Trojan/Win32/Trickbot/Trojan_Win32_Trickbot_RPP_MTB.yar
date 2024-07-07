
rule Trojan_Win32_Trickbot_RPP_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 01 53 53 6a 00 ff d6 6a 00 53 53 6a 00 ff d6 33 d2 8b c7 6a 64 59 f7 f1 8a 44 14 18 30 04 2f 47 81 ff 00 d0 07 00 7c d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}