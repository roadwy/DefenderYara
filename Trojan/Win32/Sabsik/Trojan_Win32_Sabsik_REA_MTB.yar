
rule Trojan_Win32_Sabsik_REA_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.REA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c2 66 85 ce 66 81 ca 0c 76 8b 54 24 18 88 04 2a } //1
		$a_01_1 = {88 04 29 0f be b5 c0 da 18 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}