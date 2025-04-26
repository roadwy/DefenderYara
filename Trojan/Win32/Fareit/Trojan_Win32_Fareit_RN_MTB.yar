
rule Trojan_Win32_Fareit_RN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 d4 8b 55 d4 8b 0a 03 4d e8 8b 45 d4 89 08 8b 45 08 03 45 f0 8b 10 33 55 ec 8b 45 08 03 45 f0 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}