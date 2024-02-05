
rule Trojan_Win32_Redline_GFF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 44 35 10 88 44 1d 10 88 4c 35 10 0f b6 44 1d 10 03 c2 0f b6 c0 8a 44 05 10 32 87 90 01 04 88 87 90 01 04 47 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}