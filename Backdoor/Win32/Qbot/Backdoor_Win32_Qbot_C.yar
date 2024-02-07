
rule Backdoor_Win32_Qbot_C{
	meta:
		description = "Backdoor:Win32/Qbot.C,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 2e 39 53 34 5f 41 71 75 6d 34 2e 70 64 62 } //00 00  d.9S4_Aqum4.pdb
	condition:
		any of ($a_*)
 
}