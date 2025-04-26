
rule Trojan_Win64_Reflo_NR_MTB{
	meta:
		description = "Trojan:Win64/Reflo.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 0e 48 39 c3 74 0d b9 ?? ?? ?? ?? ff d6 eb e8 31 f6 eb 05 be ?? ?? ?? ?? 48 8b 1d 2e 3f 57 00 8b 03 ff c8 75 0c } //5
		$a_01_1 = {42 00 65 00 77 00 62 00 6f 00 64 00 66 00 65 00 21 00 4e 00 6a 00 64 00 73 00 70 00 21 00 45 00 66 00 77 00 6a 00 64 00 66 00 74 00 } //1 Bewbodfe!Njdsp!Efwjdft
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}