
rule Trojan_Win32_CryptInject_OPI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.OPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 10 89 44 24 0c 0f b6 04 30 88 04 37 8b 44 24 0c 88 0c 30 8b cf 0f b6 04 31 03 c2 0f b6 c0 8a 04 30 32 83 ?? ?? ?? ?? 88 83 00 50 1c 10 f6 c3 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}