
rule Trojan_Win32_Ursnif_AT_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f9 03 f7 8b 7c 24 90 01 01 8b ce 69 f6 90 01 04 2b c8 03 ca 0f b7 d1 03 f2 8b ce 2b 0d 90 01 04 81 c3 90 01 04 89 1f 83 e9 90 01 01 83 c7 90 01 01 83 6c 24 90 01 02 0f b7 c9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}