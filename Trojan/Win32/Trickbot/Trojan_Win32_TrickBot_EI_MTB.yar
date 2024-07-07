
rule Trojan_Win32_TrickBot_EI_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 03 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 0f af 0d 90 01 04 03 c1 2b 05 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b c2 2b 05 90 01 04 2b 05 90 01 04 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 f4 0f b6 08 33 ca 8b 55 0c 03 55 f4 88 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}