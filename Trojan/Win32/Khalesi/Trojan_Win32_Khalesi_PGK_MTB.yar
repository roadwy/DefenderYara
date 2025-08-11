
rule Trojan_Win32_Khalesi_PGK_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.PGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 74 65 78 74 00 00 00 c0 78 00 00 00 10 00 00 00 7a 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0 } //5
		$a_01_1 = {2e 74 65 78 74 00 00 00 00 20 00 00 00 90 0a 00 00 14 00 00 00 30 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}