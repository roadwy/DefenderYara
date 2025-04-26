
rule Trojan_Win64_CobaltStrike_GFF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 28 40 00 00 00 c7 44 24 20 00 10 00 00 31 db 48 8d ?? ?? ?? 4c 8d 4c ?? ?? 48 89 f9 45 31 c0 ff d6 } //1
		$a_01_1 = {f3 0f 6f 0a f3 42 0f 6f 54 02 f0 f3 0f 7f 09 f3 42 0f 7f 54 01 f0 c3 } //1
		$a_01_2 = {2e 67 65 68 63 } //1 .gehc
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}