
rule Trojan_Win32_QHosts_BH{
	meta:
		description = "Trojan:Win32/QHosts.BH,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 05 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 73 74 61 74 2f 74 75 6b 2f 20 48 54 54 50 2f 31 2e 31 } //05 00  GET /stat/tuk/ HTTP/1.1
		$a_03_1 = {2f 73 74 61 74 2f 74 75 6b 2f 00 90 09 06 00 3a 90 0a 20 00 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_03_2 = {66 c7 85 37 ff ff ff 01 68 8d 85 37 ff ff ff ba 90 01 04 b1 c8 e8 90 01 04 66 c7 05 90 01 03 00 01 73 66 c7 05 90 01 03 00 01 74 90 00 } //02 00 
		$a_01_3 = {66 c7 85 09 fd ff ff 01 69 66 c7 85 d2 fd ff ff 01 5c 8d 95 d2 fd ff ff } //02 00 
		$a_01_4 = {66 c7 85 d5 fc ff ff 01 68 66 c7 85 09 fd ff ff 01 69 66 c7 85 d2 fd ff ff 01 5c } //01 00 
		$a_01_5 = {68 ee 73 74 73 20 20 00 } //01 00 
		$a_01_6 = {68 d0 be 73 74 73 00 } //01 00 
		$a_01_7 = {64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 00 00 } //01 00 
		$a_11_8 = {47 52 79 61 58 5a 6c 63 6e 4e 63 5a 58 52 6a 58 47 68 76 63 33 52 7a 00 } //00 0a  則慹婘捬乮婣剘塪桇捶刳z
	condition:
		any of ($a_*)
 
}