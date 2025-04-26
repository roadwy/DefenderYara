
rule Trojan_Win32_Trickbot_DHC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8b 55 08 89 d1 09 c1 8b 45 0c 8b 55 08 21 d0 f7 d0 21 c8 5d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}