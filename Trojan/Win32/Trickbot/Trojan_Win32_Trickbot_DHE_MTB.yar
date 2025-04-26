
rule Trojan_Win32_Trickbot_DHE_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8d 0c 07 8b c7 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 [0-03] 3b 7d ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}