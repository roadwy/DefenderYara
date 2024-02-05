
rule Trojan_Win32_Redline_NEAY_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4d d0 0f b6 04 31 8d 0c 03 8b 5d d0 88 0c 33 2a c8 88 0c 33 46 eb bf } //00 00 
	condition:
		any of ($a_*)
 
}