
rule Trojan_Win32_Redline_CAO_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0f b6 d2 0f b6 8c 35 90 02 04 03 d1 0f b6 ca 0f b6 8c 0d 90 02 04 32 88 90 02 04 88 88 90 02 04 c7 45 fc ff ff ff ff 40 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}