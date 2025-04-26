
rule Trojan_Win32_ZorRoar_A_dha{
	meta:
		description = "Trojan:Win32/ZorRoar.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 "
		
	strings :
		$a_43_0 = {c4 04 89 38 6a 00 6a 00 50 68 90 01 04 6a 00 6a 00 c7 40 04 90 05 01 04 01 02 03 04 00 00 00 ff 90 00 00 } //100
	condition:
		((#a_43_0  & 1)*100) >=100
 
}