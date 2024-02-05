
rule Trojan_Win32_Emotetcrypt_RMA_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 e1 0f 0f b6 8c 8d 90 01 04 30 48 90 01 01 8b 4d 90 01 01 03 c8 83 e1 0f 0f b6 8c 8d 90 01 04 30 48 90 01 01 83 c0 06 81 fa 00 34 02 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}