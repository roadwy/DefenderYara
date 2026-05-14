
rule Ransom_Win64_Encoder_A_AMTB{
	meta:
		description = "Ransom:Win64/Encoder.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {42 6c 61 63 6b 6f 75 74 20 54 65 6d 70 6f 72 61 72 79 20 53 65 72 76 69 63 65 } //Blackout Temporary Service  1
		$a_80_1 = {42 6c 61 63 6b 6f 75 74 2e 46 69 6c 65 5c 44 65 66 61 75 6c 74 49 63 6f 6e } //Blackout.File\DefaultIcon  1
		$a_80_2 = {42 6c 61 63 6b 6f 75 74 4d 75 74 65 78 } //BlackoutMutex  1
		$a_80_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 6c 6f 63 6b 2e 70 6e 67 } //C:\Windows\lock.png  1
		$a_80_4 = {42 6c 61 63 6b 6f 75 74 45 6e 63 72 79 70 74 6f 72 } //BlackoutEncryptor  1
		$a_80_5 = {72 65 67 20 64 65 6c 65 74 65 20 22 48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 22 20 2f 76 20 22 53 68 65 6c 6c 22 20 2f 66 } //reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}