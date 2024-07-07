
rule Trojan_Win32_Qbot_KN_MTB{
	meta:
		description = "Trojan:Win32/Qbot.KN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 5d ff 8a 1c 07 88 1c 01 88 14 07 0f b6 1c 01 0f b6 d2 03 da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 0f b6 d3 8a 14 02 30 16 ff 45 f8 8b 55 f8 3b 55 0c 7c 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}