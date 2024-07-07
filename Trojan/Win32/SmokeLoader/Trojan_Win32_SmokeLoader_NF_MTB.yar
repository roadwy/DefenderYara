
rule Trojan_Win32_SmokeLoader_NF_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 1c 03 cb 8d 14 06 33 ca 89 4c 24 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}