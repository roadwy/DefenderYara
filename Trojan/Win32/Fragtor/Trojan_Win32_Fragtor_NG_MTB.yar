
rule Trojan_Win32_Fragtor_NG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 45 bb 88 45 bd 66 89 45 be 88 45 c0 66 89 45 c1 88 45 c3 66 89 45 c4 88 45 c6 66 89 45 c7 88 45 c9 66 89 45 ca 88 45 cc 89 45 b4 89 45 fc } //10
		$a_81_1 = {5f 70 63 72 65 5f } //1 _pcre_
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}