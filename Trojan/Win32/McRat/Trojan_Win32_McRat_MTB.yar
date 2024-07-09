
rule Trojan_Win32_McRat_MTB{
	meta:
		description = "Trojan:Win32/McRat!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b ce bf 07 07 00 00 8a 14 01 80 f2 [0-01] 88 10 40 4f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}