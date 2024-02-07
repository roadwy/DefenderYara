
rule Trojan_Win32_ShadowPad_A_dha{
	meta:
		description = "Trojan:Win32/ShadowPad.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 64 00 "
		
	strings :
		$a_00_0 = {44 3a 5c 74 6f 72 74 6f 69 73 65 53 56 4e 5c 6e 73 63 35 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 6e 73 73 6f 63 6b 32 2e 70 64 62 } //64 00  D:\tortoiseSVN\nsc5\bin\Release\nssock2.pdb
		$a_00_1 = {23 23 23 45 52 52 4f 52 23 23 23 } //64 00  ###ERROR###
		$a_03_2 = {6a 40 68 00 10 00 00 68 90 02 02 00 00 6a 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}