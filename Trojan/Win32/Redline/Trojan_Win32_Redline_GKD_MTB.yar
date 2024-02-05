
rule Trojan_Win32_Redline_GKD_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 80 37 ff 80 07 9e 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}