
rule Ransom_Win32_Amnesia_SK_MTB{
	meta:
		description = "Ransom:Win32/Amnesia.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 21 } //5 YOUR FILES ARE ENCRYPTED!
		$a_01_1 = {41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 63 73 72 73 73 2e 65 78 65 } //5 Administrator\Application Data\csrss.exe
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 68 } //5 cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailuresh
		$a_01_3 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 2e 54 58 54 } //5 HOW TO DECRYPT FILES.TXT
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=15
 
}