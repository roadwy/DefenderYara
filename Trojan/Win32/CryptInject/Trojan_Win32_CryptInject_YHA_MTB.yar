
rule Trojan_Win32_CryptInject_YHA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 8b 75 cc 31 ce 0f b6 4d ?? 8b 7d f0 0f b6 5c 0f 03 31 f3 88 d8 88 44 0f 03 0f b6 45 ef 83 c0 04 88 c1 88 4d ef e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}