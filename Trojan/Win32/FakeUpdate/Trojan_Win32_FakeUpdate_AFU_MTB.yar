
rule Trojan_Win32_FakeUpdate_AFU_MTB{
	meta:
		description = "Trojan:Win32/FakeUpdate.AFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 } //01 00 
		$a_01_1 = {49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 } //00 00 
	condition:
		any of ($a_*)
 
}