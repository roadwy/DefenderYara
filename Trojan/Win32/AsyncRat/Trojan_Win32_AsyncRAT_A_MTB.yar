
rule Trojan_Win32_AsyncRAT_A_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 10 12 00 00 00 e8 ?? 93 fb ff 8b 44 24 14 8b 4c 24 18 8b 15 e8 ?? ?? 00 8b 1d ec ?? ?? 00 89 14 24 89 5c 24 04 89 44 24 08 89 4c 24 0c e8 ?? 4f ff ff 8b 44 24 14 8b 4c 24 10 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}