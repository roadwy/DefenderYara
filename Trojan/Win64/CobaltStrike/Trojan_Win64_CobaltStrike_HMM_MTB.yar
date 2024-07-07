
rule Trojan_Win64_CobaltStrike_HMM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c8 83 c8 90 01 01 ff c0 41 03 c3 41 ff c6 48 63 c8 48 8b 44 24 90 01 01 0f b6 8c 31 90 01 04 41 32 0c 02 41 88 0c 1a 49 ff c2 44 3b 74 24 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}