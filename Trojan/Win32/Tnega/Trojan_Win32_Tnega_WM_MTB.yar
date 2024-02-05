
rule Trojan_Win32_Tnega_WM_MTB{
	meta:
		description = "Trojan:Win32/Tnega.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 16 81 c6 04 00 00 00 4f 81 e9 90 01 04 39 c6 75 e8 c3 14 40 00 c3 29 fb 39 db 74 01 90 00 } //0a 00 
		$a_02_1 = {31 07 09 d1 81 eb 90 01 04 81 c7 90 01 04 39 f7 75 e7 c3 81 c3 f7 23 8e 2b ff 21 f2 39 c3 75 e5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}