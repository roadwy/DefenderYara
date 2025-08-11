
rule Trojan_Win32_Netspipe_A_dha{
	meta:
		description = "Trojan:Win32/Netspipe.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 09 48 8d 44 24 40 48 89 44 24 38 c7 44 24 30 f4 01 00 00 c7 44 24 28 00 20 00 00 c7 44 24 20 00 20 00 00 41 b9 01 00 00 00 45 33 c0 ba 03 00 00 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}