
rule Trojan_Win32_Redline_PCF_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 83 25 90 01 05 8d 0c 10 8b c2 c1 e0 90 01 01 89 4d f8 03 c7 33 c1 8b ca c1 e9 90 01 01 03 4d f0 89 45 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}