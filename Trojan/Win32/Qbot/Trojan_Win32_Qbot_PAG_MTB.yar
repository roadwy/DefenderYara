
rule Trojan_Win32_Qbot_PAG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 75 f4 8b 45 08 8a 04 02 32 04 0e 88 04 37 46 83 eb 90 01 01 75 e7 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}