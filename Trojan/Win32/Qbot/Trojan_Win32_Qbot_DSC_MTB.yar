
rule Trojan_Win32_Qbot_DSC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.DSC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 37 8b 75 d4 32 1c 0e 8b 4d d8 8b 75 c4 88 1c 31 83 c6 01 8b 4d e0 39 ce 8b 4d c0 89 75 cc 89 4d c8 89 55 d0 0f 84 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}