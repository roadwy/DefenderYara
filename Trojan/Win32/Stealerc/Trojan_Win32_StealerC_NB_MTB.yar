
rule Trojan_Win32_StealerC_NB_MTB{
	meta:
		description = "Trojan:Win32/StealerC.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 08 04 00 00 a1 90 01 04 33 c5 89 45 fc 8b 45 08 56 57 33 f6 33 ff 3b de 89 85 f8 fb ff ff 7e 42 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}