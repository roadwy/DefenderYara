
rule Trojan_BAT_Bladabindi_NH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 05 00 "
		
	strings :
		$a_03_0 = {6a 61 b7 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 06 11 04 6f 90 01 01 00 00 0a 26 07 90 00 } //01 00 
		$a_81_1 = {74 65 78 74 66 69 6c 65 2e 74 78 74 } //01 00  textfile.txt
		$a_81_2 = {4d 69 63 72 6f 73 6f 66 74 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  Microsoft\svchost.exe
		$a_81_3 = {63 6d 64 2e 65 78 65 20 2f 6b 20 70 69 6e 67 20 30 20 26 20 64 65 6c } //01 00  cmd.exe /k ping 0 & del
		$a_81_4 = {72 6f 6f 74 5c 53 65 63 75 72 69 74 79 43 65 6e 74 65 72 } //01 00  root\SecurityCenter
		$a_81_5 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //00 00  SELECT * FROM FirewallProduct
	condition:
		any of ($a_*)
 
}