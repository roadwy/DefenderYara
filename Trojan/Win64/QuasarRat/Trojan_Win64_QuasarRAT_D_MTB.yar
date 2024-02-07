
rule Trojan_Win64_QuasarRAT_D_MTB{
	meta:
		description = "Trojan:Win64/QuasarRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 43 72 79 73 69 73 45 78 70 65 72 69 6d 65 6e 74 61 6c } //02 00  main.CrysisExperimental
		$a_01_1 = {6d 61 69 6e 2e 44 43 52 59 53 49 53 } //00 00  main.DCRYSIS
	condition:
		any of ($a_*)
 
}