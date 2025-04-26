
rule Trojan_Win32_Grandoreiro_psyK_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {90 31 13 90 90 90 83 c3 04 90 90 90 90 39 cb 90 90 90 90 7c eb } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}