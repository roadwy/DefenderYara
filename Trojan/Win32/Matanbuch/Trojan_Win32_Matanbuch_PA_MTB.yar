
rule Trojan_Win32_Matanbuch_PA_MTB{
	meta:
		description = "Trojan:Win32/Matanbuch.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 08 8b 55 90 01 01 0f be 02 33 c8 66 89 8d 90 01 04 8b 4d 90 01 01 8b 55 90 01 01 8d 44 4a 02 89 85 90 01 04 8b 8d 90 01 04 66 8b 95 90 01 04 66 89 11 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}