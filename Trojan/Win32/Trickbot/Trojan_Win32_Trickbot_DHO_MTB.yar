
rule Trojan_Win32_Trickbot_DHO_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 14 53 8d 34 07 ff 15 ?? ?? ?? ?? 59 33 d2 8b c8 8b c7 f7 f1 8a 04 53 30 06 [0-04] 3b 7c 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}