
rule Trojan_Win32_Zusy_GE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {24 26 02 c3 90 13 32 c3 90 13 02 c3 90 13 32 c3 90 13 2a c3 90 13 32 c3 90 13 2a c3 90 13 c0 c8 e4 90 13 aa 90 13 83 c1 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 3f 02 c3 8d 3f 8d 3f 90 13 8d 3f 32 c3 8d 3f 02 c3 90 13 32 c3 8d 3f 8d 3f 2a c3 90 13 8d 3f 8d 3f 32 c3 8d 3f } //3
		$a_03_1 = {8d 3f 8d 3f 2a c3 8d 3f 90 13 8d 3f 8d 3f c0 c0 ?? 8d 3f 90 13 8d 3f aa 8d 3f 8d 3f 90 13 8d 3f 83 c1 ff 90 13 ac 8d 3f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}