
rule Trojan_Win32_StealC_CCHV_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 33 83 ff 0f 75 } //00 00 
	condition:
		any of ($a_*)
 
}