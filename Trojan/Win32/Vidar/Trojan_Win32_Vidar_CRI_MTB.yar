
rule Trojan_Win32_Vidar_CRI_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 f7 7d 94 8b 85 78 ff ff ff 0f be 0c 10 8b 55 90 03 55 98 0f be 02 33 c1 8b 4d 90 03 4d 98 88 01 eb c6 } //00 00 
	condition:
		any of ($a_*)
 
}