
rule Trojan_BAT_Flooder_GPA_MTB{
	meta:
		description = "Trojan:BAT/Flooder.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0d 00 00 "
		
	strings :
		$a_80_0 = {73 6c 6f 77 6c 6f 72 69 73 } //slowloris  1
		$a_80_1 = {68 74 74 70 66 6c 6f 6f 64 } //httpflood  1
		$a_80_2 = {75 64 70 66 6c 6f 6f 64 } //udpflood  1
		$a_80_3 = {64 6e 73 61 6d 70 } //dnsamp  1
		$a_80_4 = {4f 70 65 6e 65 64 20 70 6f 72 6e 68 75 62 20 6f 6e 20 76 69 63 74 69 6d 20 50 43 } //Opened pornhub on victim PC  1
		$a_80_5 = {21 77 65 62 63 61 6d } //!webcam  1
		$a_80_6 = {21 64 64 6f 73 } //!ddos  1
		$a_80_7 = {64 69 73 61 62 6c 69 6e 67 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //disabling Windows Defender  1
		$a_80_8 = {72 75 6e 6e 69 6e 67 20 72 61 74 20 61 73 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //running rat as administrator  1
		$a_80_9 = {21 6b 69 6c 6c 64 65 66 65 6e 64 65 72 } //!killdefender  2
		$a_80_10 = {6b 65 79 6c 6f 67 67 65 72 73 74 61 72 74 } //keyloggerstart  2
		$a_80_11 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //screenshot.png  2
		$a_80_12 = {44 69 73 63 6f 72 64 2e 57 65 62 53 6f 63 6b 65 74 } //Discord.WebSocket  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2) >=16
 
}