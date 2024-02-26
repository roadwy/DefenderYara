
rule Trojan_Win32_StealerC_KAA_MTB{
	meta:
		description = "Trojan:Win32/StealerC.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 30 04 31 46 3b f7 7c } //00 00 
	condition:
		any of ($a_*)
 
}