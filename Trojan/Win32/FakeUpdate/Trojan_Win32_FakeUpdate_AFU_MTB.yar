
rule Trojan_Win32_FakeUpdate_AFU_MTB{
	meta:
		description = "Trojan:Win32/FakeUpdate.AFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 } //1
		$a_01_1 = {49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 45 90 49 30 00 00 c7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}