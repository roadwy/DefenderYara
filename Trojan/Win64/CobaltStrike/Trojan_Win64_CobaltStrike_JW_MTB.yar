
rule Trojan_Win64_CobaltStrike_JW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 8a 04 02 41 8d 49 ?? 41 30 03 49 8d 42 ?? 45 33 d2 41 83 f9 ?? 4c 0f 45 d0 41 8b c1 45 33 c9 ff c3 49 ff c3 83 f8 ?? 48 63 c3 44 0f 45 c9 48 3b c2 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}