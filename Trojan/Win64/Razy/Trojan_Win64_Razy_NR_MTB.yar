
rule Trojan_Win64_Razy_NR_MTB{
	meta:
		description = "Trojan:Win64/Razy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 81 ee 04 00 00 00 41 81 f2 ?? ?? ?? ?? 66 41 81 c2 ?? ?? 44 8b 16 45 33 d3 e9 ?? ?? ?? ?? 4c 8b 0f 66 d3 f2 48 81 c7 ?? ?? ?? ?? 40 c0 ed 1e } //5
		$a_01_1 = {4a 4e 5a 4e 49 7a 47 59 42 } //1 JNZNIzGYB
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}