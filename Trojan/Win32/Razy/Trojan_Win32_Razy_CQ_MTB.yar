
rule Trojan_Win32_Razy_CQ_MTB{
	meta:
		description = "Trojan:Win32/Razy.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {21 d7 31 0b 43 68 90 02 04 8b 3c 24 83 c4 04 81 c2 90 02 04 39 c3 75 d0 90 00 } //02 00 
		$a_01_1 = {31 08 01 ff 40 21 df 21 df 39 f0 75 d7 } //00 00 
	condition:
		any of ($a_*)
 
}