
rule Trojan_Win32_Lokibot_UYTG_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.UYTG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 00 00 00 b0 10 40 00 e0 33 40 00 b4 56 40 00 c0 56 40 00 f4 33 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}