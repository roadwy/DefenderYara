
rule Trojan_Win32_Remcos_AOS_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {84 e5 30 4a 04 03 ee 0a 40 4e 4d 35 43 38 3a 5d bd 05 03 03 03 6e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}