
rule Trojan_Win32_QakBot_RPM_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af 87 94 00 00 00 89 87 94 00 00 00 8b 47 64 8b 4f 78 8b 1c 30 83 c6 04 0f af 5f 40 8b 47 50 8b d3 c1 ea 08 88 14 01 ff 47 50 8b 87 b8 00 00 00 8b 4f 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}