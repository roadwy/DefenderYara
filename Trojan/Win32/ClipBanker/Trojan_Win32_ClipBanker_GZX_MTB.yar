
rule Trojan_Win32_ClipBanker_GZX_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {55 8b ec 56 33 f6 56 ff 15 90 01 04 85 c0 74 48 53 57 6a 0d ff 15 90 01 04 8b d8 53 ff 15 90 01 04 8b f8 57 ff 15 90 01 04 83 c0 e6 3d 85 0f 00 00 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 } //00 00  CreateMutex
	condition:
		any of ($a_*)
 
}