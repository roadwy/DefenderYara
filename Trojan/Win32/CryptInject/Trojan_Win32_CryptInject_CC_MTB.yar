
rule Trojan_Win32_CryptInject_CC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 36 9c 97 01 7c ?? eb ?? 81 3d ?? ?? ?? ?? 1e 07 00 00 75 } //1
		$a_02_1 = {9c 4e 7f 46 75 ?? ?? 81 ?? 16 6d b0 2e 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}