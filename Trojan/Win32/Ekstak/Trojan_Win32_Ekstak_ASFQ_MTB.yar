
rule Trojan_Win32_Ekstak_ASFQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ae 42 4a 00 f5 9f 46 00 00 d2 0a 00 1d 59 ee 99 a4 f8 45 } //05 00 
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 66 1d 4b 00 aa 7a 47 00 00 d2 0a 00 62 22 71 08 5a d3 46 00 00 d4 } //00 00 
	condition:
		any of ($a_*)
 
}