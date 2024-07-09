
rule Trojan_Win32_VBKrypt_BJ_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4b 43 4f 47 0f 6e 04 0a 4a 42 ?? 0f 6e cb 4f 47 4b 43 0f ef c1 4f 47 4f 47 0f 7e c7 49 41 4f 47 89 3c 08 4e 46 4e 46 83 e9 28 f8 ?? 83 c1 2c 4f 47 4e 46 81 f9 ?? ?? 00 00 75 c5 4f 47 4f 47 ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}