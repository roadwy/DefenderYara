
rule Trojan_Win32_SmokeLoader_RPA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 ba 00 00 00 00 f7 75 14 8b 45 08 01 d0 0f b6 00 ba 7c 00 00 00 0f af c2 31 c1 8b 55 f4 8b 45 0c 01 d0 89 ca 88 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}