
rule Trojan_Win32_VBKrypt_AH_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {ff 37 81 fa 90 01 04 66 90 02 1f 59 90 02 1f e8 90 01 02 00 00 90 02 6f 89 0b 90 02 1f 83 c2 04 90 02 1f 83 c7 04 90 02 6f e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}