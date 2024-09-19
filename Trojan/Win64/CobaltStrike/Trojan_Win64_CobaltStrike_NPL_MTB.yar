
rule Trojan_Win64_CobaltStrike_NPL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff c8 83 c8 fc ff c0 48 98 ff c7 42 8a 0c 30 32 0c 16 41 32 0e 88 0a 48 ff c2 3b fd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}