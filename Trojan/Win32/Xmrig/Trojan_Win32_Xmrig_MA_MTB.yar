
rule Trojan_Win32_Xmrig_MA_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 10 8b 44 24 24 01 44 24 10 8b d6 c1 ea 05 03 54 24 28 8d 04 37 31 44 24 10 c7 05 90 01 04 19 36 6b ff c7 05 90 01 04 ff ff ff ff 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 c7 90 01 04 4d 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}