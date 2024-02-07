
rule Trojan_Win32_Derusbi_D_dha{
	meta:
		description = "Trojan:Win32/Derusbi.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 53 76 63 43 74 72 6c 46 6e 63 74 40 34 } //01 00  _SvcCtrlFnct@4
		$a_03_1 = {6a 40 68 00 10 00 00 68 00 50 00 00 6a 00 ff 15 90 01 04 89 45 fc 33 c0 8a 88 90 01 04 80 f1 90 01 01 88 8c 05 bc ec ff ff 40 3d 90 01 01 13 00 00 7c e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}