
rule Trojan_Win32_Cridex_AK_MTB{
	meta:
		description = "Trojan:Win32/Cridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 3c 31 0f b6 cb 01 f9 81 e1 ff 00 00 00 8b 7d e0 32 3c 0f 8b 4d e4 88 3c 31 83 c6 01 8b 4d ec 39 ce 8b 4d cc 89 55 dc 89 4d d8 89 75 d4 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}