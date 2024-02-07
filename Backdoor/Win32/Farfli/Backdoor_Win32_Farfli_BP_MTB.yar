
rule Backdoor_Win32_Farfli_BP_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 c5 89 45 fc c6 45 ec 4b c6 45 ed 45 c6 45 ee 52 c6 45 ef 4e c6 45 f0 45 c6 45 f1 4c c6 45 f2 33 c6 45 f3 32 c6 45 f4 2e c6 45 f5 64 c6 45 f6 6c c6 45 f7 6c c6 45 f8 00 c6 45 d0 47 c6 45 d1 65 c6 45 d2 74 c6 45 d3 50 c6 45 d4 72 } //02 00 
		$a_01_1 = {63 59 72 65 65 6e 51 69 6c 6c 74 68 68 74 } //00 00  cYreenQillthht
	condition:
		any of ($a_*)
 
}