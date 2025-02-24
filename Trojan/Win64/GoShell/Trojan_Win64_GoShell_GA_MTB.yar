
rule Trojan_Win64_GoShell_GA_MTB{
	meta:
		description = "Trojan:Win64/GoShell.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 fd 78 5f 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 60 48 89 c1 48 39 44 24 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}