
rule Trojan_Win64_ArcaneStealer_ARC_MTB{
	meta:
		description = "Trojan:Win64/ArcaneStealer.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 72 63 61 6e 65 70 61 6e 65 6c 2e 63 63 } //3 arcanepanel.cc
		$a_01_1 = {42 72 75 74 65 2e 74 78 74 } //1 Brute.txt
		$a_01_2 = {61 72 63 61 6e 65 5f 62 6f 75 6e 64 61 72 79 } //1 arcane_boundary
		$a_01_3 = {41 00 72 00 63 00 61 00 6e 00 65 00 55 00 70 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 31 00 2e 00 30 00 } //1 ArcaneUploader/1.0
		$a_01_4 = {41 00 72 00 63 00 61 00 6e 00 65 00 2f 00 31 00 2e 00 30 00 } //1 Arcane/1.0
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}