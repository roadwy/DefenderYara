
rule Trojan_BAT_Stratork_B{
	meta:
		description = "Trojan:BAT/Stratork.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 22 20 2f 76 20 22 57 69 6e 64 6f 77 73 20 4c 69 76 65 73 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 25 65 78 65 25 } //1 Run" /v "Windows Lives" /t REG_SZ /d %exe%
		$a_01_1 = {70 61 63 3d 66 69 6c 65 3a 2f 2f 25 41 50 50 44 41 54 41 3a 5c 3d 2f 25 2f 25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 2e 70 61 63 } //1 pac=file://%APPDATA:\=/%/%COMPUTERNAME%.pac
		$a_01_2 = {65 63 68 6f 20 22 41 75 74 6f 43 6f 6e 66 69 67 55 52 4c 22 3d 22 25 70 61 63 25 22 20 3e 3e 20 22 25 61 70 70 64 61 74 61 25 5c 25 55 53 45 52 4e 41 4d 45 25 2e 72 65 67 } //1 echo "AutoConfigURL"="%pac%" >> "%appdata%\%USERNAME%.reg
		$a_01_3 = {63 6f 70 79 20 22 25 74 65 6d 70 25 5c 6c 65 69 61 6d 65 2e 74 78 74 22 20 22 25 61 70 70 64 61 74 61 25 5c 25 43 4f 4d 50 55 54 45 52 4e 41 4d 45 25 2e 70 61 63 } //1 copy "%temp%\leiame.txt" "%appdata%\%COMPUTERNAME%.pac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}