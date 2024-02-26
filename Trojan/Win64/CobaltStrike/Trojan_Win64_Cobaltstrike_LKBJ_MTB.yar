
rule Trojan_Win64_Cobaltstrike_LKBJ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.LKBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 ff c3 32 43 ff 48 ff c6 88 46 ff 48 39 fb 75 ea } //00 00 
	condition:
		any of ($a_*)
 
}