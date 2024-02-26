
rule Trojan_Win32_StealC_CCGL_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 31 83 fb 0f 75 19 } //00 00 
	condition:
		any of ($a_*)
 
}