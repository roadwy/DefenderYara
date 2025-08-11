
rule Trojan_Win64_Lotok_NC_MTB{
	meta:
		description = "Trojan:Win64/Lotok.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {38 31 35 34 39 33 38 39 33 39 3a 41 41 46 76 32 32 6d 41 55 57 59 6b 39 79 41 76 6f 64 48 55 4e 68 44 4f 62 43 31 79 62 5a 6b 4b 58 41 51 } //2 8154938939:AAFv22mAUWYk9yAvodHUNhDObC1ybZkKXAQ
		$a_01_1 = {63 75 72 6c 20 2d 73 20 69 66 63 6f 6e 66 69 67 2e 6d 65 20 3e 20 69 70 2e 74 78 74 } //1 curl -s ifconfig.me > ip.txt
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {4d 79 41 75 74 6f 53 74 61 72 74 41 70 70 } //1 MyAutoStartApp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}