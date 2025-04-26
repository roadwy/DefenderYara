
rule Trojan_Win32_Pikabot_IP_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.IP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}