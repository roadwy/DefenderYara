
rule Trojan_Win32_Grandoreiro_psyZ_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 25 a4 41 42 00 90 90 00 00 00 00 ff 25 b0 41 42 00 90 90 00 00 00 00 ff 25 b4 41 42 00 90 90 00 00 00 00 ff 25 b8 41 42 00 90 90 00 00 00 00 ff 25 bc 41 42 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}