
rule Trojan_Win32_Trickbot_DHI_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d5 33 d2 8b c6 b9 [0-04] f7 f1 8a 04 3e 8a 14 1a 32 c2 88 04 3e 8b 44 24 [0-04] 46 3b f0 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}