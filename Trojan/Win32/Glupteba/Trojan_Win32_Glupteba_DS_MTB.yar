
rule Trojan_Win32_Glupteba_DS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {29 db 09 db 31 10 09 ff 81 eb a4 1b 7d cd 40 81 eb 01 00 00 00 39 f0 75 } //03 00 
		$a_01_1 = {b9 c0 59 50 3f 81 c0 57 2c 06 57 31 3b 09 c8 b9 4f fc ce 7f 81 c3 01 00 00 00 01 c9 29 c8 39 d3 75 } //02 00 
		$a_01_2 = {57 81 c1 6d 5a 24 91 5b 09 d1 41 40 4a 29 d2 81 f8 2e f3 00 01 75 } //02 00 
		$a_01_3 = {53 29 d2 5f 81 c0 9d dd 4a 1a 81 c1 01 00 00 00 40 01 c2 81 f9 d5 88 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}