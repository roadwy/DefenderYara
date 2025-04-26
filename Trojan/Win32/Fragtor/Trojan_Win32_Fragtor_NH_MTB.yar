
rule Trojan_Win32_Fragtor_NH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 45 c7 88 45 c9 66 89 45 ca 88 45 cc 66 89 45 cd 88 45 cf 66 89 45 d0 88 45 d2 66 89 45 d3 88 45 } //10
		$a_81_1 = {5f 70 63 72 65 5f } //1 _pcre_
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}