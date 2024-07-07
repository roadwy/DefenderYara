
rule Trojan_Win32_StealC_CYD_MTB{
	meta:
		description = "Trojan:Win32/StealC.CYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 01 83 fb 0f 75 19 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}