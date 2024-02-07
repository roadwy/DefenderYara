
rule Backdoor_BAT_AsyncRAT_ZB_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {61 74 74 72 69 62 20 2b 68 20 2b 72 20 2b 73 } //01 00  attrib +h +r +s
		$a_81_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //01 00  netsh firewall delete allowedprogram
		$a_81_2 = {53 45 45 5f 4d 41 53 4b 5f 4e 4f 5a 4f 4e 45 43 48 45 43 4b 53 } //01 00  SEE_MASK_NOZONECHECKS
		$a_81_3 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 30 20 2d 6e 20 32 20 26 20 64 65 6c } //00 00  cmd.exe /c ping 0 -n 2 & del
	condition:
		any of ($a_*)
 
}