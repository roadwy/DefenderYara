
rule Trojan_Win32_Tofsee_AMI_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 03 cb 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 } //4
		$a_03_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 03 c7 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c1 33 44 24 ?? 2b d8 89 44 24 ?? 8b c3 c1 e0 04 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}