
rule Trojan_Win32_SystemBC_psyM_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.psyM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {be 00 d0 40 00 8d be 00 40 ff ff 57 89 e5 8d 9c 24 80 c1 ff ff 31 c0 50 39 dc 75 fb 46 46 53 68 ba 86 02 00 57 83 c3 04 53 68 e6 df 01 00 56 83 c3 04 53 50 c7 03 03 00 02 00 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}