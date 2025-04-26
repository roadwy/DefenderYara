
rule Backdoor_MacOS_ReverseShell_A{
	meta:
		description = "Backdoor:MacOS/ReverseShell.A,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 69 70 65 00 66 6f 72 6b 00 2f 62 69 6e 2f 73 68 00 73 68 00 65 78 65 63 6c 00 35 31 2e 38 39 2e 32 32 2e 31 34 36 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}