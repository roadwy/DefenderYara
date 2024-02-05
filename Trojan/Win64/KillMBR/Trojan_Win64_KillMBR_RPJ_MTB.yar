
rule Trojan_Win64_KillMBR_RPJ_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 15 6d 1d 00 00 48 63 c3 f0 80 34 38 23 ff c3 81 fb ff 01 00 00 72 e3 } //00 00 
	condition:
		any of ($a_*)
 
}