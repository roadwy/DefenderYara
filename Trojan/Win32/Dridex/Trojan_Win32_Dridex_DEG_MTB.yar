
rule Trojan_Win32_Dridex_DEG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 10 05 90 01 04 89 07 a3 90 01 04 0f b7 05 90 01 04 8b fe 6b ff 4a 90 00 } //1
		$a_02_1 = {2b f3 83 e8 1b 8b 15 90 01 04 8b 5c 24 10 81 c2 90 01 04 89 15 90 01 04 89 13 8b d0 2b d1 81 ea 90 01 04 0f b7 ca 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}