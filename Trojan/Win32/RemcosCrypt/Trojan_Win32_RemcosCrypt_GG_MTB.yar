
rule Trojan_Win32_RemcosCrypt_GG_MTB{
	meta:
		description = "Trojan:Win32/RemcosCrypt.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 04 99 8b 55 90 01 01 8b 4d 90 01 01 33 04 8a 8b 55 90 01 01 8b 4d 90 01 01 89 04 8a 66 a1 90 02 04 66 3b 05 90 0a 3c 00 8b 15 90 02 04 33 15 90 02 04 3b 15 90 02 04 8b 4d 90 01 01 8b 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}