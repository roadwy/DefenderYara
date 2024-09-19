
rule Trojan_Win32_Luca_MKV_MTB{
	meta:
		description = "Trojan:Win32/Luca.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 8b c7 8d 76 04 c1 ea 04 83 c7 04 8b ca c1 e1 04 03 ca 2b c1 8b 4c 24 ?? 03 c5 0f b6 44 04 27 32 44 31 fc 88 46 ff 81 ff 00 28 0c 00 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}