
rule Trojan_Win32_StealC_SPXX_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 45 f0 8b 45 f0 31 45 e8 8b 45 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}