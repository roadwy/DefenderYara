
rule Trojan_Win32_Redline_FD_MTB{
	meta:
		description = "Trojan:Win32/Redline.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 ff 15 34 11 40 00 ff 45 fc 81 7d fc } //00 00 
	condition:
		any of ($a_*)
 
}