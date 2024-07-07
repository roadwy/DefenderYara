
rule Trojan_Win32_Neoreblamy_D_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 59 89 06 89 46 90 01 01 8d 04 98 89 46 90 01 01 89 7d fc 8b 0e 8b c3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}