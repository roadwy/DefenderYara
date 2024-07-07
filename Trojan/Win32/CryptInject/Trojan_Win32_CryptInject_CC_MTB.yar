
rule Trojan_Win32_CryptInject_CC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 36 9c 97 01 7c 90 01 01 eb 90 01 01 81 3d 90 01 04 1e 07 00 00 75 90 00 } //1
		$a_02_1 = {9c 4e 7f 46 75 90 01 02 81 90 01 01 16 6d b0 2e 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}