
rule Trojan_Win32_PecardoStealer_RPZ_MTB{
	meta:
		description = "Trojan:Win32/PecardoStealer.RPZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ac 32 c2 2a c2 32 c2 c0 c0 03 fe c8 32 c2 02 d6 aa e2 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}