
rule Trojan_Win32_Virlock_PADQ_MTB{
	meta:
		description = "Trojan:Win32/Virlock.PADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 6e 00 00 00 8a 06 90 32 c2 90 88 07 90 42 46 47 90 49 90 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}