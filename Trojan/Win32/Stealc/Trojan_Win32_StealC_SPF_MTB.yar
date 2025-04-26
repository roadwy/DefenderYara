
rule Trojan_Win32_StealC_SPF_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 45 e4 8b 45 f8 33 45 e4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}