
rule Backdoor_Linux_NetWiredRC_A{
	meta:
		description = "Backdoor:Linux/NetWiredRC.A,SIGNATURE_TYPE_MACHOHSTR_EXT,15 00 15 00 09 00 00 "
		
	strings :
		$a_03_0 = {2f 74 6d 70 2f 25 73 00 43 4f 4e 4e 45 43 54 90 01 01 25 73 3a 25 64 90 01 01 48 54 54 50 90 00 } //5
		$a_01_1 = {2f 74 6d 70 2f 2e 25 73 00 25 73 2f 25 73 2e 61 70 70 00 25 73 2f 43 6f 6e 74 65 6e 74 73 } //5 琯灭ⸯ猥─⽳猥愮灰─⽳潃瑮湥獴
		$a_01_2 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 select *  from moz_logins
		$a_01_3 = {25 73 2f 4c 69 62 72 61 72 79 2f 53 65 61 4d 6f 6e 6b 65 79 } //1 %s/Library/SeaMonkey
		$a_01_4 = {25 73 2f 2e 4c 69 62 72 61 72 79 2f 54 68 75 6e 64 65 72 62 69 72 64 } //1 %s/.Library/Thunderbird
		$a_01_5 = {25 73 2f 2e 4c 69 62 72 61 72 79 2f 4f 70 65 72 61 2f 77 61 6e 64 2e 64 61 74 } //1 %s/.Library/Opera/wand.dat
		$a_01_6 = {25 73 2f 2e 4c 69 62 72 61 72 79 2f 4d 6f 7a 69 6c 6c 61 2f 46 69 72 65 66 6f 78 } //1 %s/.Library/Mozilla/Firefox
		$a_01_7 = {25 73 2f 4c 69 62 72 61 72 79 2f 41 70 70 6c 69 63 61 74 69 6f 6e 20 53 75 70 70 6f 72 74 2f 46 69 72 65 66 6f 78 } //1 %s/Library/Application Support/Firefox
		$a_01_8 = {52 47 49 32 38 44 51 33 30 51 42 38 51 31 46 37 } //10 RGI28DQ30QB8Q1F7
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*10) >=21
 
}
rule Backdoor_Linux_NetWiredRC_A_2{
	meta:
		description = "Backdoor:Linux/NetWiredRC.A,SIGNATURE_TYPE_ELFHSTR_EXT,20 00 1e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 73 25 73 07 25 73 00 47 45 54 20 25 73 20 48 54 54 50 } //5
		$a_01_1 = {25 73 2f 2e 63 6f 6e 66 69 67 2f 61 75 74 6f 73 74 61 72 74 2f 25 73 2e 64 65 73 6b 74 6f 70 } //5 %s/.config/autostart/%s.desktop
		$a_03_2 = {5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 90 01 01 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d 90 00 } //5
		$a_01_3 = {25 73 2f 2e 63 6f 6e 66 69 67 2f 67 6f 6f 67 6c 65 2d 63 68 72 6f 6d 65 2f 44 65 66 61 75 6c 74 2f 4c 6f 67 69 6e } //1 %s/.config/google-chrome/Default/Login
		$a_01_4 = {25 73 2f 2e 63 6f 6e 66 69 67 2f 63 68 72 6f 6d 69 75 6d 2f 44 65 66 61 75 6c 74 2f 4c 6f 67 69 6e } //1 %s/.config/chromium/Default/Login
		$a_01_5 = {73 65 6c 65 63 74 20 2a 20 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 select *  from moz_logins
		$a_01_6 = {25 73 2f 2e 74 68 75 6e 64 65 72 62 69 72 64 2f 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s/.thunderbird/profiles.ini
		$a_01_7 = {25 73 2f 2e 6f 70 65 72 61 2f 77 61 6e 64 2e 64 61 74 } //1 %s/.opera/wand.dat
		$a_01_8 = {25 73 2f 2e 70 75 72 70 6c 65 2f 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //1 %s/.purple/accounts.xml
		$a_01_9 = {25 73 2f 2e 6d 6f 7a 69 6c 6c 61 2f 66 69 72 65 66 6f 78 2f 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s/.mozilla/firefox/profiles.ini
		$a_01_10 = {52 47 49 32 38 44 51 33 30 51 42 38 51 31 46 37 } //10 RGI28DQ30QB8Q1F7
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*10) >=30
 
}