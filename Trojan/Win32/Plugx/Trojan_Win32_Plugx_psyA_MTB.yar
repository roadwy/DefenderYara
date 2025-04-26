
rule Trojan_Win32_Plugx_psyA_MTB{
	meta:
		description = "Trojan:Win32/Plugx.psyA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 90 04 46 00 50 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 33 c0 89 08 50 45 43 6f 6d } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}