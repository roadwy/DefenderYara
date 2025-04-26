
rule Trojan_Win32_CryptInject_KKV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.KKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 d1 0f b6 d2 89 55 08 8a 55 f0 02 55 08 02 55 f8 0f b6 d2 0f b6 5c ?? 04 8d 54 ?? 04 89 55 08 8b 55 0c 30 5c 16 ff 8b 55 08 8b 12 31 17 8b 7c 88 04 03 7d ec 8b 55 f4 31 3a 3b 75 10 0f 8c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}