
rule Trojan_Win64_Farfli_KK_MTB{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 43 10 48 ff c7 80 74 07 ff 22 48 ff c9 } //20
		$a_01_1 = {48 ff c2 41 ff c1 49 3b d3 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}
rule Trojan_Win64_Farfli_KK_MTB_2{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 30 05 48 ff c0 48 ff c9 } //20
		$a_01_1 = {80 30 05 48 ff c0 49 ff cc } //10
		$a_01_2 = {47 6c 6f 62 61 6c 5c 44 48 47 47 6c 6f 62 61 6c 4d 75 74 65 78 } //5 Global\DHGGlobalMutex
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}
rule Trojan_Win64_Farfli_KK_MTB_3{
	meta:
		description = "Trojan:Win64/Farfli.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 64 6c 6c c6 45 ?? 00 c7 45 ?? 69 6c 65 54 c7 45 ?? 69 6d 65 00 c7 45 ?? 69 6c 65 54 c7 45 ?? 69 6d 65 00 c7 45 ?? 54 69 6d 65 } //20
		$a_01_1 = {80 30 46 48 8d 40 01 ff c1 81 f9 08 02 00 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}