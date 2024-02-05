
rule Trojan_Win32_AveMariaRAT_A_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 8a 44 15 98 30 04 19 41 81 f9 } //00 00 
	condition:
		any of ($a_*)
 
}