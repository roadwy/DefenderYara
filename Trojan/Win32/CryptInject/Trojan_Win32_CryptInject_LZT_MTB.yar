
rule Trojan_Win32_CryptInject_LZT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.LZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce 83 e1 1f d3 e8 33 d2 b9 d0 01 00 00 89 45 f8 8b c6 f7 f1 8b 4d f8 8b c7 46 32 0c 02 8b 55 08 32 cb 88 4c 16 ?? d1 eb 83 fe 20 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}