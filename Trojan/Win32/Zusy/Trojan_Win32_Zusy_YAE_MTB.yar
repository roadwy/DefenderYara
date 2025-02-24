
rule Trojan_Win32_Zusy_YAE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 c3 e9 60 90 0a 05 00 32 c3 90 13 8d 3f 90 13 02 c3 90 13 32 c3 90 13 8d 3f e9 } //10
		$a_01_1 = {5f 63 40 67 30 51 c3 32 c3 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}