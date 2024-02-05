
rule Trojan_Win32_Amadey_ADM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 fa 03 0f b6 45 90 01 01 c1 e0 05 0b d0 88 55 90 01 01 0f b6 4d 90 01 01 f7 d9 88 4d 90 01 01 0f b6 55 90 01 01 f7 d2 88 55 90 01 01 0f b6 45 90 01 01 c1 f8 06 0f b6 4d 90 01 01 c1 e1 02 0b c1 88 45 90 01 01 0f b6 55 90 01 01 2b 55 90 01 01 88 55 90 01 01 8b 90 01 01 bc 8a 4d ee 88 4c 05 94 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}