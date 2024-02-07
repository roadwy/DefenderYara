
rule Spammer_Win32_Baxin{
	meta:
		description = "Spammer:Win32/Baxin,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 63 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 73 00 5f 00 6d 00 73 00 6e 00 5f 00 63 00 73 00 5f 00 70 00 74 00 62 00 72 00 40 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 6c 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 3e 00 } //01 00  <communications_msn_cs_ptbr@microsoft.windowslive.com>
		$a_01_1 = {74 00 75 00 64 00 6f 00 5c 00 62 00 61 00 69 00 78 00 61 00 20 00 64 00 61 00 72 00 6c 00 61 00 6d 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //00 00  tudo\baixa darlam\Project1.vbp
	condition:
		any of ($a_*)
 
}