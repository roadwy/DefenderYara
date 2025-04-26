
rule Backdoor_Linux_WireNet_A_xp{
	meta:
		description = "Backdoor:Linux/WireNet.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {25 73 2f 2e 6f 70 65 72 61 2f 77 61 6e 64 2e 64 61 74 } //1 %s/.opera/wand.dat
		$a_00_1 = {25 73 2f 2e 6d 6f 7a 69 6c 6c 61 2f 73 65 61 6d 6f 6e 6b 65 79 2f 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s/.mozilla/seamonkey/profiles.ini
		$a_00_2 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //1 select * from moz_logins
		$a_00_3 = {25 73 2f 2e 63 6f 6e 66 69 67 2f 61 75 74 6f 73 74 61 72 74 } //1 %s/.config/autostart
		$a_00_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //1 encryptedPassword
		$a_00_5 = {63 72 6f 6e 74 61 62 20 2f 74 6d 70 2f 6e 63 74 66 2e 74 78 74 } //1 crontab /tmp/nctf.txt
		$a_00_6 = {25 73 2f 2e 74 68 75 6e 64 65 72 62 69 72 64 2f 70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //1 %s/.thunderbird/profiles.ini
		$a_00_7 = {25 73 2f 2e 78 69 6e 69 74 72 63 } //1 %s/.xinitrc
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=4
 
}