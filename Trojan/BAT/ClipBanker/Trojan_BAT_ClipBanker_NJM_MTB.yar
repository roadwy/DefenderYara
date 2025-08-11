
rule Trojan_BAT_ClipBanker_NJM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {60 66 11 06 5a 17 5f 16 2e 11 00 11 06 66 1f 40 5f 1f 40 } //2
		$a_81_1 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 7b 30 7d 22 20 2f 74 72 20 22 7b 31 7d 22 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f 20 31 20 2f 49 54 20 2f 46 } //1 /c schtasks /create /tn "{0}" /tr "{1}" /SC MINUTE /MO 1 /IT /F
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_81_3 = {75 44 4b 36 71 34 4a 67 61 64 39 67 38 4e 54 4d 4b 75 57 4a 61 6f 76 52 42 43 78 76 4b 58 4d 59 7a 74 61 75 } //1 uDK6q4Jgad9g8NTMKuWJaovRBCxvKXMYztau
		$a_81_4 = {55 73 65 72 4f 4f 42 45 42 72 6f 6b 65 72 } //1 UserOOBEBroker
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}