
rule Trojan_Win32_PecardoStealer_RPM_MTB{
	meta:
		description = "Trojan:Win32/PecardoStealer.RPM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 c8 07 c0 c8 07 2a c1 c0 c8 07 04 43 2c 43 c0 c0 07 34 47 c0 c8 07 aa 4a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}