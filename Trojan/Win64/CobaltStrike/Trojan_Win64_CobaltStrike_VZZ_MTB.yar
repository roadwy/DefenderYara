
rule Trojan_Win64_CobaltStrike_VZZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff c1 0f b6 c9 44 0f b6 4c 0d ?? 44 00 ca 44 0f b6 c2 46 0f b6 54 05 d0 44 88 54 0d d0 46 88 4c 05 d0 44 02 4c 0d d0 45 0f b6 c9 46 0f b6 4c 0d d0 45 30 0c 07 48 ff c0 49 39 c6 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}