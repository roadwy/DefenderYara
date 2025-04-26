
rule Trojan_Win64_Bazarldr_ZZ_MTB{
	meta:
		description = "Trojan:Win64/Bazarldr.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 C:\Windows\explorer.exe
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b } //1 Software\Microsoft\Windows\CurrentVersion\Policies\Network
		$a_03_3 = {4c 8b c7 48 8b d8 33 c0 48 85 db 48 8b cb 0f 45 d0 89 15 [0-04] 48 8b d6 e8 [0-04] 48 8b 74 24 38 48 8b c3 48 8b 5c 24 30 48 83 c4 ?? 5f c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}