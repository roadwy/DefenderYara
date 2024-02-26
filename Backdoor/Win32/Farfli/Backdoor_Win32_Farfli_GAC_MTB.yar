
rule Backdoor_Win32_Farfli_GAC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 5d e8 c6 45 ec 43 c6 45 ed 72 c6 45 ee 65 c6 45 ef 61 c6 45 f0 74 c6 45 f1 65 c6 45 f2 45 c6 45 f3 76 c6 45 f4 65 c6 45 f5 6e c6 45 f6 74 c6 45 f7 41 88 5d f8 ff d7 50 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}