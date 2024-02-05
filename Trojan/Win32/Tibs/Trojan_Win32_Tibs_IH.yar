
rule Trojan_Win32_Tibs_IH{
	meta:
		description = "Trojan:Win32/Tibs.IH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 18 be db 90 01 03 ff 94 90 01 05 61 b9 90 01 04 c9 c2 90 00 } //01 00 
		$a_01_1 = {bb 05 ee 0f 00 81 f3 45 ee 0f 00 8d 55 } //00 00 
	condition:
		any of ($a_*)
 
}