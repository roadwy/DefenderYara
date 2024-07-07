
rule Trojan_Win64_CobaltStrike_LKAC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 81 6c 01 00 00 b8 90 01 04 2b 05 90 01 04 41 01 41 64 48 63 0d 90 01 04 49 8b 81 18 01 00 00 44 88 04 01 ff 05 90 01 04 49 81 fa 00 dd 01 00 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}