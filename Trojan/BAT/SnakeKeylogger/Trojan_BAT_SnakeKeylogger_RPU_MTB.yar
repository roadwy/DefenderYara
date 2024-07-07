
rule Trojan_BAT_SnakeKeylogger_RPU_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 cdn.discordapp.com
		$a_01_1 = {4a 00 6a 00 72 00 74 00 6c 00 6a 00 73 00 63 00 2e 00 70 00 6e 00 67 00 } //1 Jjrtljsc.png
		$a_01_2 = {43 00 74 00 61 00 65 00 70 00 61 00 71 00 77 00 78 00 73 00 79 00 77 00 } //1 Ctaepaqwxsyw
		$a_01_3 = {57 65 62 52 65 73 70 6f 6e 73 65 } //1 WebResponse
		$a_01_4 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}