
rule Trojan_Win64_CobaltStrike_LKBA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8d 0c 00 47 8d 0c 89 41 89 d2 45 29 ca 41 80 ca 90 01 01 46 88 54 04 2a 49 ff c0 83 c2 90 01 01 83 fa 12 77 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}