
rule Trojan_Win32_SmokeLoader_HR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 cb 33 4d 90 01 01 33 4d 90 01 01 2b f1 89 4d 90 01 01 89 75 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 83 0d 90 01 05 8b c6 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 ff 75 90 01 01 8b c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}