
rule Trojan_Win64_ReverseShell_ARS_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8d 95 d0 0f 00 00 b8 00 00 00 00 b9 1e 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04 } //1
		$a_01_1 = {48 8b 85 b0 13 00 00 8b 48 0c 48 8b 85 b0 13 00 00 8b 50 08 48 8b 85 b0 13 00 00 8b 40 04 41 89 c8 89 c1 } //1
		$a_01_2 = {48 8b 85 b0 13 00 00 48 8b 40 10 89 c1 48 8b 85 b0 13 00 00 48 8b 50 20 48 8b 85 b8 13 00 00 41 89 c8 48 89 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}