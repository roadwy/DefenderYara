
rule Trojan_Win32_Trickbot_ZY{
	meta:
		description = "Trojan:Win32/Trickbot.ZY,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 3b 45 f8 73 25 8b 45 0c 0f b6 00 66 0f be d0 8b 45 fc 66 89 10 8b 45 0c 0f b6 00 84 c0 74 0a 83 45 fc 02 83 45 0c 01 eb d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}