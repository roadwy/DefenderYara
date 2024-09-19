
rule Trojan_Win64_Strela_GA_MTB{
	meta:
		description = "Trojan:Win64/Strela.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 28 88 13 00 00 48 c7 44 24 20 00 00 00 00 41 b9 10 00 00 00 31 c9 4c 89 ?? 4d 89 } //10
		$a_01_1 = {41 b8 00 30 00 00 41 b9 40 00 00 00 31 c9 } //1
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}
rule Trojan_Win64_Strela_GA_MTB_2{
	meta:
		description = "Trojan:Win64/Strela.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,31 00 2e 00 0f 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 31 36 2e 30 5c 4f 75 74 6c 6f 6f 6b 5c 50 72 6f 66 69 6c 65 73 5c 4f 75 74 6c 6f 6f 6b 5c 39 33 37 35 43 46 46 30 34 31 33 31 31 31 64 33 42 38 38 41 30 30 31 30 34 42 32 41 36 36 37 36 } //SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676  20
		$a_80_1 = {2f 73 65 72 76 65 72 2e 70 68 70 } ///server.php  10
		$a_80_2 = {2f 6f 75 74 2e 70 68 70 } ///out.php  10
		$a_80_3 = {6d 73 63 6f 72 65 65 2e 64 6c 6c } //mscoree.dll  5
		$a_80_4 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //AppPolicyGetProcessTerminationMethod  5
		$a_80_5 = {50 4f 53 54 } //POST  1
		$a_80_6 = {5c 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 } //\Thunderbird\Profiles  1
		$a_80_7 = {4d 6f 7a 69 6c 6c 61 2f } //Mozilla/  1
		$a_80_8 = {49 4d 41 50 20 55 73 65 72 } //IMAP User  1
		$a_80_9 = {49 4d 41 50 20 53 65 72 76 65 72 } //IMAP Server  1
		$a_80_10 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //IMAP Password  1
		$a_80_11 = {25 73 25 73 5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //%s%s\logins.json  1
		$a_80_12 = {25 73 25 73 5c 6b 65 79 34 2e 64 62 } //%s%s\key4.db  1
		$a_80_13 = {4d 65 73 73 61 67 65 42 6f 78 54 69 6d 65 6f 75 74 41 } //MessageBoxTimeoutA  1
		$a_80_14 = {52 74 6c 50 63 54 6f 46 69 6c 65 48 65 61 64 65 72 } //RtlPcToFileHeader  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=46
 
}