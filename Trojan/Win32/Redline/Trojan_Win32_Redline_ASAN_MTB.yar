
rule Trojan_Win32_Redline_ASAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe ff 50 e8 90 01 02 fe ff 80 34 1f 90 00 } //01 00 
		$a_03_1 = {fe ff 50 e8 90 01 02 fe ff 80 04 1f 90 01 01 83 c4 30 47 3b fe 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}