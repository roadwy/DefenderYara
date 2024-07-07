
rule Trojan_Win32_PikaBot_CCCE_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 07 83 c7 90 01 01 0f af 59 90 01 01 8b 46 90 01 01 35 90 01 04 0f af 81 90 01 04 89 81 90 01 04 a1 90 01 04 8b 80 90 01 04 33 86 90 01 04 2d 90 01 04 01 46 90 01 01 8b 86 90 01 04 33 46 90 01 01 8b 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}