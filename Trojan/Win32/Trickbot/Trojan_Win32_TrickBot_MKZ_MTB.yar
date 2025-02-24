
rule Trojan_Win32_TrickBot_MKZ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 03 32 d7 88 54 24 02 8a e0 88 44 24 ?? 80 f4 c0 22 e0 c0 e8 06 0a c6 83 c7 fd 88 44 24 ?? 88 64 24 04 0f b6 c3 8b dd 0f b6 04 03 88 06 0f b6 44 24 02 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}