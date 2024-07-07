
rule Trojan_Win32_Neoreblamy_RP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}