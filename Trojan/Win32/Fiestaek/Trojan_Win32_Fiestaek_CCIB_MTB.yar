
rule Trojan_Win32_Fiestaek_CCIB_MTB{
	meta:
		description = "Trojan:Win32/Fiestaek.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 90 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}