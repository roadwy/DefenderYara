
rule Trojan_Win32_Gozi_RM_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b7 71 14 03 f1 8b ce 8b f0 03 cf 81 f6 db 5a 17 43 8b f8 03 f1 89 54 24 1c } //00 00 
	condition:
		any of ($a_*)
 
}