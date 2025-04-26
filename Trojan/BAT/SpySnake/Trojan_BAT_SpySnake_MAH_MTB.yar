
rule Trojan_BAT_SpySnake_MAH_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 12 04 28 ?? ?? ?? 0a 07 08 02 08 91 6f ?? ?? ?? 0a de 0b 11 04 2c 06 09 28 ?? ?? ?? 0a dc 08 25 17 59 0c 16 fe 02 13 05 2b 04 13 04 2b d1 11 05 2d 02 2b 05 2b c3 0d 2b c3 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 13 06 2b 03 26 2b 9c 11 06 2a } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {74 00 6f 00 72 00 61 00 65 00 63 00 68 00 2e 00 63 00 6f 00 6d 00 } //1 toraech.com
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}