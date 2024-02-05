
rule Trojan_Win32_GandCrypt_GH_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 90 01 04 8b 15 90 01 04 69 d2 fd 43 03 00 89 15 90 01 04 81 05 90 01 04 c3 9e 26 00 a0 90 01 04 30 04 1e 46 3b f7 7c 90 00 } //01 00 
		$a_02_1 = {3d 4a 38 02 00 7e 90 01 01 ba db 86 00 00 66 3b ca 75 90 01 01 40 3d 59 68 00 00 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}