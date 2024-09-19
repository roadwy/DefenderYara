
rule Trojan_Win32_DarkGate_MKV_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 13 2b c8 2b ce 8a 44 0c 24 32 87 ?? ?? ?? ?? 88 04 2f 47 81 ff 00 ca 16 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}