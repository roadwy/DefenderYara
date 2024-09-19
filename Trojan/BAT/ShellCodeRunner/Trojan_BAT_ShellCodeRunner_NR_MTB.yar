
rule Trojan_BAT_ShellCodeRunner_NR_MTB{
	meta:
		description = "Trojan:BAT/ShellCodeRunner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 09 11 04 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 16 fe 0e ee 01 } //3
		$a_01_1 = {52 56 69 72 75 73 2e 70 64 62 } //1 RVirus.pdb
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}