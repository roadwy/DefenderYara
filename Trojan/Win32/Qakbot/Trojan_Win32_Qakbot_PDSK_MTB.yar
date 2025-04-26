
rule Trojan_Win32_Qakbot_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PDSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 01 8b 44 24 24 0f b6 14 10 01 fa 88 d7 0f b6 d7 8a 3c 10 30 df 8b 54 24 44 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}