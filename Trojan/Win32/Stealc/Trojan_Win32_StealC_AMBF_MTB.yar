
rule Trojan_Win32_StealC_AMBF_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 31 45 e8 8b 45 e8 33 d0 89 45 fc 89 55 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}