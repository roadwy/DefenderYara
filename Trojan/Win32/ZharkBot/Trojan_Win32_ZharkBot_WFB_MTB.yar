
rule Trojan_Win32_ZharkBot_WFB_MTB{
	meta:
		description = "Trojan:Win32/ZharkBot.WFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2 8a c8 c0 e1 03 2a c8 c0 e1 03 8a 45 dc 2a c1 04 39 8b 4d dc 30 84 0d b1 f6 ff ff 41 89 4d dc 83 f9 33 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}