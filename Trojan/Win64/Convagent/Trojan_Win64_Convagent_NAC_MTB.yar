
rule Trojan_Win64_Convagent_NAC_MTB{
	meta:
		description = "Trojan:Win64/Convagent.NAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {2f 43 20 73 63 20 63 72 65 61 74 65 20 58 62 6c 47 61 6d 65 20 62 69 6e 50 61 74 68 3d 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 61 74 61 5c 6d 64 77 73 6c 70 2e 65 78 65 22 20 73 74 61 72 74 3d 20 61 75 74 6f } //2 /C sc create XblGame binPath="C:\Users\Public\data\mdwslp.exe" start= auto
		$a_81_1 = {2f 43 20 73 63 20 73 74 61 72 74 20 58 62 6c 47 61 6d 65 } //1 /C sc start XblGame
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 61 74 61 5c 7a 63 72 78 64 65 62 75 67 2e 74 78 74 } //1 C:\Users\Public\data\zcrxdebug.txt
		$a_81_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 73 69 67 6e 74 6f 6f 6c 2e 65 78 65 } //1 C:\Windows\System32\signtool.exe
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 64 61 74 61 5c 6d 64 77 73 6c 70 2e 65 78 65 } //1 C:\Users\Public\data\mdwslp.exe
		$a_02_5 = {44 00 3a 00 5c 00 77 00 6f 00 72 00 6b 00 5c 00 5f 00 5f 00 63 00 68 00 72 00 6f 00 6d 00 65 00 5f 00 65 00 78 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 5f 00 5f 00 6d 00 79 00 5f 00 73 00 72 00 63 00 5c 00 73 00 72 00 63 00 5c 00 5f 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-1f] 2e 00 70 00 64 00 62 00 } //1
		$a_02_6 = {44 3a 5c 77 6f 72 6b 5c 5f 5f 63 68 72 6f 6d 65 5f 65 78 5f 69 6e 73 74 61 6c 6c 5c 5f 5f 6d 79 5f 73 72 63 5c 73 72 63 5c 5f 52 65 6c 65 61 73 65 5c [0-1f] 2e 70 64 62 } //1
		$a_81_7 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 4e 65 77 2d 53 65 6c 66 53 69 67 6e 65 64 43 65 72 74 69 66 69 63 61 74 65 20 2d 54 79 70 65 20 43 6f 64 65 53 69 67 6e 69 6e 67 20 2d 53 75 62 6a 65 63 74 20 27 43 4e 3d 61 61 61 27 20 2d 4b 65 79 55 73 61 67 65 20 44 69 67 69 74 61 6c 53 69 67 6e 61 74 75 72 65 } //1 powershell -Command "New-SelfSignedCertificate -Type CodeSigning -Subject 'CN=aaa' -KeyUsage DigitalSignature
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}