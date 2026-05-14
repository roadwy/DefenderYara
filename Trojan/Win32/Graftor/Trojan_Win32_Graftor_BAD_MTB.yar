
rule Trojan_Win32_Graftor_BAD_MTB{
	meta:
		description = "Trojan:Win32/Graftor.BAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe c3 8a 93 60 14 40 00 02 c2 8a 88 60 14 40 00 88 8b 60 14 40 00 88 90 60 14 40 00 02 ca 8a 89 60 14 40 00 30 0e 46 4f 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}