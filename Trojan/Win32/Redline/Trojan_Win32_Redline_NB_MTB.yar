
rule Trojan_Win32_Redline_NB_MTB{
	meta:
		description = "Trojan:Win32/Redline.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {56 53 31 db 81 ec 90 01 04 8b 7d 0c 3b 5d 10 90 01 02 89 d8 31 d2 8d 8d 90 01 04 f7 75 14 8b 45 08 0f be 34 10 e8 90 01 04 8d 8d 90 01 04 e8 90 01 04 69 c6 90 01 04 30 04 1f 43 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}