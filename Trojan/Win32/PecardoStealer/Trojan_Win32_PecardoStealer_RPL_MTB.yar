
rule Trojan_Win32_PecardoStealer_RPL_MTB{
	meta:
		description = "Trojan:Win32/PecardoStealer.RPL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 2a c1 c0 c0 03 2a c1 32 c1 2c 5e 2a c1 2c 5e 34 32 2a c1 04 5e 04 5e 32 c1 34 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}