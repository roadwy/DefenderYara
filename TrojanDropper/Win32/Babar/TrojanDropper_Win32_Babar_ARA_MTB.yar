
rule TrojanDropper_Win32_Babar_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Babar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 f7 89 f0 31 db 83 c7 90 01 01 81 2e 90 01 04 83 c6 04 66 ba 5d e9 39 fe 7c ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}