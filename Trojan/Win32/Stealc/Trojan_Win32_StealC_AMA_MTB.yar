
rule Trojan_Win32_StealC_AMA_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f 5e 20 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}