
rule Trojan_Win32_Glupteba_GAF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {d8 85 40 00 81 c7 90 01 04 e8 90 01 04 21 ff 01 db 31 06 01 df 81 c6 90 01 04 39 ce 75 90 00 } //0a 00 
		$a_03_1 = {d8 85 40 00 68 90 01 04 8b 34 24 83 c4 04 29 c6 e8 90 01 04 81 ee 90 01 04 46 31 3a 42 40 81 e8 90 01 04 39 da 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}