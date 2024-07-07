
rule Trojan_Win32_Qbot_PAR_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 2b 8a 14 28 2a 54 24 90 01 01 8b 47 90 01 01 32 54 24 90 01 01 83 7c 24 90 01 02 88 14 01 0f 84 90 01 04 8b 47 90 01 01 8d 34 2b 8b 4c 24 90 01 01 b2 01 d2 e2 fe ca 8a 2c 06 8b 44 24 90 01 01 22 ea 88 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}