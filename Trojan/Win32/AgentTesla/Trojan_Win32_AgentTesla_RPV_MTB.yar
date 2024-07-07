
rule Trojan_Win32_AgentTesla_RPV_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8d 7f 01 b9 3f 00 00 00 4e f7 f1 8a 44 15 a8 88 47 ff 85 f6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}