
rule Trojan_Win32_StealC_SPXC_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 ec 20 a1 90 01 04 33 c5 89 45 fc 81 ff 82 01 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}