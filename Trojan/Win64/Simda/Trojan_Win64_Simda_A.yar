
rule Trojan_Win64_Simda_A{
	meta:
		description = "Trojan:Win64/Simda.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 01 49 ff c0 32 c2 80 c2 0d 0f b6 c0 66 89 01 48 8b 03 4a 8d 0c 40 } //1
		$a_01_1 = {66 83 38 4f 75 19 66 83 78 02 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}