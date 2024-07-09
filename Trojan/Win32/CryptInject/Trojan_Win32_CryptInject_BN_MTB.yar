
rule Trojan_Win32_CryptInject_BN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {88 44 04 08 40 3d ?? ?? 00 00 72 f4 } //1
		$a_02_1 = {0f b6 44 34 14 0f b6 d3 03 c2 99 b9 ?? ?? 00 00 f7 f9 45 0f b6 54 14 14 30 55 ff 83 bc 24 50 0c 00 00 00 75 } //1
		$a_00_2 = {83 c4 1c ff d6 5f 5e 5d b0 01 5b 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}