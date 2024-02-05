
rule Trojan_Win32_Emotetcrypt_VR_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f2 ae f7 d1 49 90 02 02 f7 f1 8a 0c 90 02 02 8b 54 90 02 02 8a 04 90 02 02 32 c8 8b 44 90 02 02 46 88 0b 3b f0 75 90 01 01 5f 5d 5b 5e c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}