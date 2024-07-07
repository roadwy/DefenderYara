
rule Trojan_Win32_Tnega_GMS_MTB{
	meta:
		description = "Trojan:Win32/Tnega.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c3 84 fd 30 f9 0f 98 c5 89 c7 c0 c1 02 } //10
		$a_01_1 = {4d 74 67 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c } //1 MtgKERNEL32.dll
		$a_01_2 = {44 6f 6e 57 53 32 5f 33 32 2e 64 6c 6c } //1 DonWS2_32.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}