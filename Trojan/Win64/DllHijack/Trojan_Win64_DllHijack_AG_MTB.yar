
rule Trojan_Win64_DllHijack_AG_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 45 f7 48 8b 55 10 48 98 0f b6 54 02 02 4c 8b 45 ?? 48 8b 45 f8 4c 01 c0 31 ca 88 10 48 83 45 f8 01 48 8b 45 f8 48 3b 45 ?? 0f } //4
		$a_03_1 = {b9 e8 03 00 00 48 8b 05 b1 50 01 00 ff d0 8b 05 ?? ?? ?? 00 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}