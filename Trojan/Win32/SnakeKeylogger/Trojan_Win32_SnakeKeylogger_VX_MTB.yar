
rule Trojan_Win32_SnakeKeylogger_VX_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.VX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a8 8b 4d bc 8b 55 ac 83 7d c4 00 0f 95 c3 80 f3 ff 80 e3 01 0f b6 f3 89 34 24 89 54 24 04 89 4c 24 08 89 44 24 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}