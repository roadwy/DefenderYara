
rule Trojan_Win32_Zenpak_CAQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c2 29 c2 89 35 [0-04] 8d 05 [0-04] ff e0 29 c2 48 31 1d [0-04] 8d 05 [0-04] 01 38 ba 05 00 00 00 b8 08 00 00 00 89 d0 40 8d 05 [0-04] 01 28 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}