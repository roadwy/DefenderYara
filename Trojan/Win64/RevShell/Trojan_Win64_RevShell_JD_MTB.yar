
rule Trojan_Win64_RevShell_JD_MTB{
	meta:
		description = "Trojan:Win64/RevShell.JD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 d0 48 89 44 24 48 48 8d 45 f0 48 89 44 24 40 48 c7 44 24 38 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 08 c7 44 24 20 01 00 00 00 48 8b 85 90 00 00 00 41 b9 00 00 00 00 41 b8 00 00 00 00 48 8d 15 a9 29 00 00 b9 00 00 00 00 ff d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}