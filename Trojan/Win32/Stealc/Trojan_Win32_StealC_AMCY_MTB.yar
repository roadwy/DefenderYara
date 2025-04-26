
rule Trojan_Win32_StealC_AMCY_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 f7 fb 8b 04 97 31 04 8e 41 83 f9 ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}