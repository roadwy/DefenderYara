
rule Trojan_Win32_Farfli_BT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b ce 7c } //02 00 
		$a_01_1 = {8a 14 01 80 ea 46 80 f2 19 88 14 01 41 3b ce 7c } //00 00 
	condition:
		any of ($a_*)
 
}