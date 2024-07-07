
rule Trojan_Win32_Trickbot_DHD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 1c 8b 54 24 20 8b c1 8b f2 f7 d0 f7 d6 83 c4 90 01 01 0b c6 0b ca 23 c1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}