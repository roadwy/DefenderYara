
rule Trojan_Win32_OffLoader_JMAA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.JMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {e8 b2 9b fa ff 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 5a 52 } //02 00 
		$a_01_1 = {e8 cf 74 fa ff 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 84 db 34 89 34 89 34 89 34 89 34 89 34 } //01 00 
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //01 00  /silent
		$a_01_3 = {2f 00 77 00 65 00 61 00 6b 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //01 00  /weaksecurity
		$a_01_4 = {2f 00 6e 00 6f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //01 00  /nocookies
		$a_01_5 = {2f 00 70 00 6f 00 70 00 75 00 70 00 } //01 00  /popup
		$a_01_6 = {2f 00 72 00 65 00 73 00 75 00 6d 00 65 00 } //01 00  /resume
		$a_01_7 = {2f 00 75 00 73 00 65 00 72 00 61 00 67 00 65 00 6e 00 74 00 } //01 00  /useragent
		$a_01_8 = {2f 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 } //01 00  /connecttimeout
		$a_01_9 = {2f 00 74 00 6f 00 73 00 74 00 61 00 63 00 6b 00 63 00 6f 00 6e 00 76 00 } //00 00  /tostackconv
	condition:
		any of ($a_*)
 
}