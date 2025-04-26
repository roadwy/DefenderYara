
rule Trojan_Win32_CryptInject_RHB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 68 58 32 50 78 7a 48 7a 71 6e 74 2e 74 69 70 } //1 dhX2PxzHzqnt.tip
		$a_01_1 = {3f 48 69 64 65 50 6f 69 6e 74 65 72 4f 72 69 67 69 6e 61 6c 40 40 59 47 46 4b 50 41 49 50 41 44 3c 56 } //1 ?HidePointerOriginal@@YGFKPAIPAD<V
		$a_03_2 = {2e 64 61 74 61 00 00 00 ?? 2f 01 00 00 d0 01 00 00 dc 00 00 00 c2 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 00 e0 2e 72 73 72 63 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}