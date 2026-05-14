
rule Trojan_Win64_CobaltStrike_CP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c2 0f 57 c3 f3 0f 6f 4c 01 ?? f3 0f 7f 40 ?? 0f 57 ca 0f 57 cb f3 0f 7f 48 ?? 49 83 e8 01 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}