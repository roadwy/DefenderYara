
rule Trojan_Win32_Cridex_FO_MTB{
	meta:
		description = "Trojan:Win32/Cridex.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 14 81 c1 90 01 04 89 4c 24 10 89 0d 90 01 04 89 0f b9 90 01 04 2b c8 0f af ca 81 c1 90 01 04 03 ce 83 7c 24 18 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}