
rule Trojan_Win32_PikaBot_YX_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.YX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 14 07 83 c7 04 a1 90 01 04 8b 80 90 01 04 33 46 90 01 01 35 90 01 04 89 46 90 01 01 a1 90 01 04 05 90 01 04 03 c1 a3 90 01 04 a1 90 01 04 8b 5e 90 01 01 0f af da 8b 88 90 01 04 8b 86 90 01 04 8b d3 c1 ea 90 01 01 88 14 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}