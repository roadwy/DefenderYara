
rule Trojan_Win64_CobaltStrike_QE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 88 04 0c 83 c2 ?? 48 ff c1 48 83 f9 ?? 7c } //1
		$a_03_1 = {33 c9 4d 8d 49 ?? 48 83 f8 ?? 48 0f 45 c8 0f b6 04 0c 41 30 41 ?? 48 8d 41 ?? 48 83 ea ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}