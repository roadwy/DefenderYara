
rule Trojan_Win32_Emotetcrypt_VZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 fa 88 54 90 01 02 0f b6 14 90 01 01 88 14 90 01 01 88 04 90 01 01 0f b6 14 90 01 01 0f b6 04 90 01 01 03 c2 99 f7 fb 0f b6 90 01 01 0f b6 14 90 01 01 90 17 04 01 01 01 01 30 31 32 33 90 01 02 83 6c 90 01 02 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}