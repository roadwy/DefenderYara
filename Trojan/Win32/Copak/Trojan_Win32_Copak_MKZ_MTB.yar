
rule Trojan_Win32_Copak_MKZ_MTB{
	meta:
		description = "Trojan:Win32/Copak.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d1 be de 5a 6f a9 81 c1 01 00 00 00 f7 d6 f7 d6 31 3b 29 ce 41 81 c3 02 00 00 00 81 e9 01 00 00 00 be 40 3e df 8f 81 c1 8f 5d 9f aa 39 d3 0f 8c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}