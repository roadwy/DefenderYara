
rule Trojan_Win32_Fareit_RPF_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 01 c8 56 81 f6 90 02 64 5e 31 30 51 81 c9 90 00 } //1
		$a_01_1 = {59 39 18 0f 85 89 fe ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}