
rule Trojan_Win32_Danabot_DEA_MTB{
	meta:
		description = "Trojan:Win32/Danabot.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 ce 8d 5c 0b 1a 8b cb 2b ce 41 89 0d 90 01 04 69 f6 1d 53 00 00 03 f0 81 c2 90 01 04 0f b7 fe 8b 74 24 10 89 16 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}