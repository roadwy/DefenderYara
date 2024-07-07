
rule Trojan_Win32_Lokibot_JHK_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 7d 0c 00 66 8b 06 74 0e 66 3b 44 4d 90 01 01 75 0e 66 8b 90 01 03 eb 13 66 3b 90 01 03 74 07 41 3b cf 72 dd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}