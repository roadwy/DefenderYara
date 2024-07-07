
rule Trojan_Win32_VBKrypt_AG_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 f1 85 c0 85 ff eb 90 02 ff 66 90 01 04 89 0b eb 90 02 6f 83 c2 04 85 d2 66 90 01 04 eb 90 02 6f 83 c7 04 66 90 01 04 81 ff 90 01 04 eb 90 02 6f 81 fa 90 01 02 00 00 0f 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}