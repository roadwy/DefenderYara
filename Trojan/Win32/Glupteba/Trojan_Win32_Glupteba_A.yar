
rule Trojan_Win32_Glupteba_A{
	meta:
		description = "Trojan:Win32/Glupteba.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 74 6e 65 74 5f 74 40 62 6f 74 40 } //02 00  botnet_t@bot@
		$a_03_1 = {73 65 72 76 65 72 2d 25 73 2e 90 02 0a 2e 72 75 3a 33 30 2c 73 65 72 76 65 72 2d 25 73 2e 90 02 0a 2e 72 75 3a 33 30 2c 73 65 72 76 65 72 2d 25 73 2e 90 00 } //01 00 
		$a_01_2 = {53 65 6e 64 20 73 74 61 74 20 69 6e 66 6f 20 74 6f } //01 00  Send stat info to
		$a_01_3 = {75 70 74 69 6d 65 3d 25 64 26 64 6f 77 6e 6c 69 6e 6b 3d 25 64 26 75 70 6c 69 6e 6b 3d 25 64 26 69 64 3d 25 73 26 73 74 61 74 70 61 73 73 3d 25 73 26 76 65 72 73 69 6f 6e 3d 25 64 26 66 65 61 74 75 72 65 73 3d 25 64 26 67 75 69 64 3d 25 73 26 63 6f 6d 6d 65 6e 74 3d 25 73 26 70 3d 25 64 26 73 3d 25 73 } //00 00  uptime=%d&downlink=%d&uplink=%d&id=%s&statpass=%s&version=%d&features=%d&guid=%s&comment=%s&p=%d&s=%s
	condition:
		any of ($a_*)
 
}