
rule Trojan_Win32_Virlock_LMX_MTB{
	meta:
		description = "Trojan:Win32/Virlock.LMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 42 46 90 47 90 49 90 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}