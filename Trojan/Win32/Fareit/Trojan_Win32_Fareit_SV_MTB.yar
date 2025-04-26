
rule Trojan_Win32_Fareit_SV_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {47 43 4e 75 90 0a 17 00 8b cf b2 ?? 8a 03 e8 af ff ff ff } //1
		$a_01_1 = {32 c2 88 01 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}