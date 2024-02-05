
rule Trojan_Win32_Glupteba_DH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 17 81 c6 d0 8d 4e a3 46 81 c7 04 00 00 00 09 f1 89 f3 39 c7 75 } //00 00 
	condition:
		any of ($a_*)
 
}