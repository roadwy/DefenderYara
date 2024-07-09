
rule Trojan_Win64_ReverseShell_CCAG_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.CCAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 85 10 02 00 00 48 89 45 ?? 48 8b 85 ?? ?? ?? ?? 48 89 45 48 ?? 8b 85 ?? ?? ?? ?? 48 89 45 } //1
		$a_01_1 = {31 35 39 2e 38 39 2e 32 31 34 2e 33 31 } //1 159.89.214.31
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}