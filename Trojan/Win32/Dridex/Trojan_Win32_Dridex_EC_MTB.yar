
rule Trojan_Win32_Dridex_EC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 74 21 65 21 21 7c 6a 74 85 6a 45 04 68 57 64 63 66 6a 74 40 75 cf 68 04 74 03 21 6a 78 64 64 8b 63 6a 74 68 05 78 85 6a 20 8b 66 } //01 00 
		$a_01_1 = {50 45 43 32 4e 4f } //01 00  PEC2NO
		$a_01_2 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 } //00 00  golfinfo.ini
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 00 72 00 75 00 6c 00 65 00 39 00 61 00 62 00 75 00 6e 00 64 00 61 00 6e 00 74 00 6c 00 79 00 4d 00 61 00 64 00 65 00 6d 00 6f 00 76 00 65 00 74 00 68 00 2c 00 6e 00 } //01 00  6rule9abundantlyMademoveth,n
		$a_01_1 = {32 00 68 00 69 00 6d 00 67 00 72 00 61 00 73 00 73 00 } //01 00  2himgrass
		$a_01_2 = {39 00 6b 00 50 00 44 00 6f 00 6e 00 2e 00 74 00 62 00 65 00 61 00 73 00 74 00 7a 00 73 00 61 00 69 00 64 00 4f 00 } //01 00  9kPDon.tbeastzsaidO
		$a_01_3 = {78 00 6c 00 65 00 74 00 2c 00 72 00 75 00 6c 00 65 00 74 00 34 00 } //00 00  xlet,rulet4
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {47 65 29 4d 6f 64 20 6c 65 48 } //Ge)Mod leH  03 00 
		$a_80_1 = {4c 62 72 61 47 79 45 78 34 } //LbraGyEx4  03 00 
		$a_80_2 = {26 54 68 75 73 20 70 3e 67 67 72 3d 69 20 63 3d 6a 6e 6f 40 20 62 65 6c 72 75 6e 7c 6d 6e } //&Thus p>ggr=i c=jno@ belrun|mn  03 00 
		$a_80_3 = {49 4f 62 69 74 } //IObit  03 00 
		$a_80_4 = {4d 61 69 6c 41 73 53 6d 74 70 53 65 72 76 65 72 } //MailAsSmtpServer  03 00 
		$a_80_5 = {55 70 6c 6f 61 64 56 69 61 48 74 74 70 } //UploadViaHttp  03 00 
		$a_80_6 = {62 75 67 72 65 70 6f 72 74 2e 74 78 74 } //bugreport.txt  03 00 
		$a_80_7 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //screenshot.png  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_EC_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.EC!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b0 e5 c6 44 24 33 74 8a 4c 24 33 8a 54 24 1f 88 54 24 51 38 c8 0f 84 17 ff ff ff eb 89 31 c0 c7 44 24 2c 1e 06 } //00 00 
	condition:
		any of ($a_*)
 
}