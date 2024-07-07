
rule Trojan_Win32_PlugX_RPQ_MTB{
	meta:
		description = "Trojan:Win32/PlugX.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 10 80 c3 fc 88 1c 10 40 3b c1 7c f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}