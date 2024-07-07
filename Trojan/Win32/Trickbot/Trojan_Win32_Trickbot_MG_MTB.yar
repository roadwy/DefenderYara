
rule Trojan_Win32_Trickbot_MG_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 8b 74 24 90 01 01 55 53 8b 5c 24 90 01 01 8b 90 01 01 33 90 01 01 bd 90 02 04 f7 f5 8a 90 01 02 8a 90 01 02 32 90 01 01 88 90 01 02 41 3b cf 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}