
rule Trojan_Win32_DorkBot_RPX_MTB{
	meta:
		description = "Trojan:Win32/DorkBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d7 d3 ea 03 c7 03 55 d8 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}