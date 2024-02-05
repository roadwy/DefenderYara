
rule Trojan_Win32_Razy_CV_MTB{
	meta:
		description = "Trojan:Win32/Razy.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 19 89 d0 41 81 c2 90 02 04 52 5a 39 f1 75 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}