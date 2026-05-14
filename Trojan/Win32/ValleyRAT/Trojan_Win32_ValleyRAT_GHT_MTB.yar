
rule Trojan_Win32_ValleyRAT_GHT_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8b f1 57 6a 40 68 00 30 00 00 8b 46 04 2b 06 50 6a 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff ?? ?? 8b 16 8b 4e 04 2b ca 51 52 57 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 6a 00 6a 00 57 6a 00 6a 00 ff 15 ?? ?? ?? ?? 85 c0 74 09 6a ff 50 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}