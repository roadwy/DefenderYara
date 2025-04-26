
rule Trojan_Win32_Zenpak_BT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 ce 81 e6 ff 00 00 00 8b 8d ec fe ff ff 8b 9d c0 fe ff ff 8a 0c 19 32 8c 35 f4 fe ff ff 8b b5 e8 fe ff ff 88 0c 1e 8b 8d f0 fe ff ff 39 cf 8b 8d [0-04] 89 95 [0-04] 89 8d [0-04] 89 bd [0-04] 0f } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}