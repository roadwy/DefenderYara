
rule Trojan_Win32_Zenpak_AZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 c6 81 c6 90 01 04 8b 06 0f b7 33 31 c6 01 ce 81 ff 90 01 04 89 f0 89 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}