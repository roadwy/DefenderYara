
rule Trojan_Win32_Zenpak_AG_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d1 89 c8 99 f7 fe 8a bc 15 f4 fe ff ff 8b 8d b8 fe ff ff 88 bc 0d f4 fe ff ff 88 9c 15 f4 fe ff ff 0f b6 b4 0d f4 fe ff ff 8b 8d bc fe ff ff 01 ce 81 e6 ff 00 00 00 8b 8d ec fe ff ff 8b 9d c4 fe ff ff 8a 0c 19 32 8c 35 f4 fe ff ff 8b b5 e8 fe ff ff 88 0c 1e 8b 8d f0 fe ff ff 39 cf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}