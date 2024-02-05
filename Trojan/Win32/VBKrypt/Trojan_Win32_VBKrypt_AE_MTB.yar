
rule Trojan_Win32_VBKrypt_AE_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 0f 57 c8 81 90 02 ff 39 18 75 90 02 ff ff d0 90 02 ff 8b 1c 17 90 02 10 31 f3 90 02 10 11 1c 10 90 02 10 83 c2 04 90 02 10 81 fa 90 01 02 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}