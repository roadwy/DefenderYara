
rule Trojan_Win32_Chapak_EAEA_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EAEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f4 8b 45 f8 8b 55 f0 03 c1 8a 14 02 41 88 10 89 4d f4 3b 0d dc 94 42 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}