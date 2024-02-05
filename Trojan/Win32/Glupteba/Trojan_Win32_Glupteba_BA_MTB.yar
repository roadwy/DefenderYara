
rule Trojan_Win32_Glupteba_BA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 32 68 98 50 18 6c 5b 81 c2 90 01 04 29 d8 39 fa 75 e7 01 c3 81 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Glupteba_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 db 74 01 ea 31 11 81 c1 04 00 00 00 39 f9 75 ef } //02 00 
		$a_03_1 = {89 34 24 81 eb 90 02 04 81 eb 90 02 04 4b 58 21 d9 47 29 d9 81 ff a5 ca 00 01 75 bc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}