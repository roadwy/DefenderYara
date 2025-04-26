
rule PWS_BAT_Telbot_GA_MTB{
	meta:
		description = "PWS:BAT/Telbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_80_0 = {42 6f 74 6e 65 74 } //Botnet  1
		$a_80_1 = {54 65 6c 65 67 72 61 6d } //Telegram  1
		$a_80_2 = {68 74 74 70 3a 2f 2f 69 70 69 6e 66 6f 2e 69 6f 2f 69 70 } //http://ipinfo.io/ip  1
		$a_80_3 = {73 6f 6c 61 72 77 69 6e 64 73 } //solarwinds  1
		$a_80_4 = {45 74 68 65 72 65 61 6c } //Ethereal  1
		$a_80_5 = {4d 65 67 61 44 75 6d 70 65 72 } //MegaDumper  1
		$a_80_6 = {64 6e 73 70 79 } //dnspy  1
		$a_80_7 = {42 6f 74 43 6c 69 65 6e 74 } //BotClient  1
		$a_80_8 = {48 49 2c 20 59 4f 55 20 41 52 45 20 42 4f 54 20 56 49 43 54 49 4d } //HI, YOU ARE BOT VICTIM  1
		$a_80_9 = {43 68 72 6f 6d 65 } //Chrome  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=9
 
}