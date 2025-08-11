
rule Trojan_Win32_Badur_EGRP_MTB{
	meta:
		description = "Trojan:Win32/Badur.EGRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d bc 8b 55 a4 8b 04 8a 33 45 f8 8b 4d bc 8b 55 cc 89 04 8a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}