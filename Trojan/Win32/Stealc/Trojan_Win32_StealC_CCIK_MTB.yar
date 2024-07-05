
rule Trojan_Win32_StealC_CCIK_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 c7 30 08 83 fb 0f 75 } //00 00 
	condition:
		any of ($a_*)
 
}