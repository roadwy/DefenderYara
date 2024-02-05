
rule Trojan_Win32_IcedID_PKV_MTB{
	meta:
		description = "Trojan:Win32/IcedID.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {81 c2 5c 60 2d 01 89 15 90 01 04 a1 90 01 04 03 45 fc 8b 0d 90 01 04 89 88 90 01 02 ff ff 90 09 06 00 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}