
rule Trojan_Win32_Adload_DSK_MTB{
	meta:
		description = "Trojan:Win32/Adload.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f be 0c 10 8b 15 90 01 04 0f b6 84 15 90 01 02 ff ff 33 c1 8b 0d 90 01 04 88 84 0d 90 01 02 ff ff eb 90 09 05 00 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}