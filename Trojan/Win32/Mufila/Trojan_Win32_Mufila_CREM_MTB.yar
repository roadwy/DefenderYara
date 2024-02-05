
rule Trojan_Win32_Mufila_CREM_MTB{
	meta:
		description = "Trojan:Win32/Mufila.CREM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 c8 03 45 bc 0f b6 c8 8b 55 0c 03 55 f8 0f b6 02 8b 55 d4 33 04 8a 8b 4d 0c 03 4d f8 88 01 eb } //00 00 
	condition:
		any of ($a_*)
 
}