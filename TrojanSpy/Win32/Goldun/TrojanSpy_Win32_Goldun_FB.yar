
rule TrojanSpy_Win32_Goldun_FB{
	meta:
		description = "TrojanSpy:Win32/Goldun.FB,SIGNATURE_TYPE_PEHSTR,28 00 23 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 2f 61 63 63 74 2f 61 69 2e 61 73 70 3f 63 3d 41 53 } //0a 00  Referer: https://www.e-gold.com/acct/ai.asp?c=AS
		$a_01_1 = {59 46 48 74 79 32 35 5c 30 30 74 30 70 30 30 2e 65 78 65 } //0a 00  YFHty25\00t0p00.exe
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 69 6e 74 65 6c 33 2e 64 6c 6c } //05 00  C:\WINDOWS\SYSTEM32\intel3.dll
		$a_01_3 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //05 00  C:\WINDOWS\SYSTEM32\drivers\etc\hosts
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //00 00  SOFTWARE\Microsoft\Internet Account Manager\Accounts
	condition:
		any of ($a_*)
 
}