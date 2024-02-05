
rule Trojan_Win32_Grandoreiro_psyN_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {be 00 b0 41 00 8d be 00 60 fe ff 57 89 e5 8d 9c 24 80 c1 ff ff 31 c0 50 39 dc 75 fb 46 46 53 68 94 23 02 00 57 83 c3 04 53 68 2f 96 00 00 56 83 c3 04 53 50 c7 03 03 00 02 } //00 00 
	condition:
		any of ($a_*)
 
}