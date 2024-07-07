
rule Trojan_Win32_VBKrypt_BK_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 0a fc 50 90 02 1f c1 fb 00 81 f3 90 01 04 eb 90 02 4f c1 ca 00 83 f6 00 c1 fb 00 c1 e1 00 89 1c 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}