
rule Trojan_Win32_Stealer_D{
	meta:
		description = "Trojan:Win32/Stealer.D,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3a 00 20 00 4e 00 30 00 74 00 5f 00 43 00 6f 00 75 00 6e 00 74 00 72 00 79 00 } //01 00  Country: N0t_Country
		$a_01_1 = {2a 00 62 00 6c 00 6f 00 63 00 6b 00 63 00 68 00 61 00 69 00 6e 00 2a 00 2e 00 78 00 6c 00 73 00 78 00 } //01 00  *blockchain*.xlsx
		$a_01_2 = {25 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 25 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 73 00 65 00 63 00 72 00 65 00 74 00 2e 00 74 00 78 00 74 00 } //01 00  %USERPROFILE%\Desktop\secret.txt
		$a_01_3 = {2a 00 65 00 6c 00 65 00 63 00 74 00 72 00 75 00 6d 00 2a 00 2e 00 74 00 78 00 74 00 } //00 00  *electrum*.txt
	condition:
		any of ($a_*)
 
}