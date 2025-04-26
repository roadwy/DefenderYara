
rule Trojan_Win32_Rozena_RPF_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RPF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 fc 30 04 31 8a 04 31 2a 45 fb 88 04 31 32 45 fa 88 04 31 02 45 f9 88 04 31 32 45 f8 88 04 31 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}