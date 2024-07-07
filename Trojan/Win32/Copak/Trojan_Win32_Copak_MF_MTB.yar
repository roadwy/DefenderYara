
rule Trojan_Win32_Copak_MF_MTB{
	meta:
		description = "Trojan:Win32/Copak.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 8f 97 a1 c2 ba d8 85 40 00 09 c9 e8 1f 00 00 00 29 c8 31 13 09 c8 81 c0 34 cd ca 66 81 c3 01 00 00 00 39 fb 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}