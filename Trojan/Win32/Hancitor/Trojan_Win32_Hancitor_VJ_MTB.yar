
rule Trojan_Win32_Hancitor_VJ_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.VJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {02 db 2a 5c 24 1c 8b 4c 24 10 80 eb 2e 83 44 24 0c 04 81 c1 64 40 02 01 89 0f 02 da 89 0d 90 01 04 8b 0d 90 01 04 0f b6 fb 83 c1 f8 03 cf 89 7c 24 10 33 ff 89 4c 24 1c 83 6c 24 18 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}