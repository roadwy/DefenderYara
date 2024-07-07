
rule Trojan_Win32_Emotetcrypt_VT_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a 90 02 02 8b 44 90 02 02 30 4c 90 02 02 3b 74 90 02 02 7c 90 02 01 8b 90 02 03 8a 90 02 03 8a 90 02 03 5f 5d 5b 88 90 02 01 88 90 02 02 5e 59 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}