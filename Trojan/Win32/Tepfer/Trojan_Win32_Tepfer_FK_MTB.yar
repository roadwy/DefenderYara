
rule Trojan_Win32_Tepfer_FK_MTB{
	meta:
		description = "Trojan:Win32/Tepfer.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 85 90 01 02 ff ff 83 c0 64 89 85 90 01 02 ff ff 83 ad 90 01 02 ff ff 64 8a 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 30 14 30 83 7d 90 01 01 0f 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}