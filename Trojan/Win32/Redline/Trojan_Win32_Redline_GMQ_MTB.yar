
rule Trojan_Win32_Redline_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 04 2f 90 01 01 ff d6 80 34 2f 90 01 01 ff d6 80 04 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}