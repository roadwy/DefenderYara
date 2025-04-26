
rule Trojan_BAT_Lokibot_MA_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 72 76 65 72 31 2e 65 78 65 } //1 server1.exe
		$a_80_1 = {52 65 63 6f 76 65 72 79 20 54 6f 6f 6c } //Recovery Tool  1
		$a_00_2 = {46 61 69 6c 46 61 73 74 } //1 FailFast
		$a_00_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_4 = {6a 00 6e 00 6f 00 69 00 74 00 20 00 59 00 6f 00 74 00 } //5 jnoit Yot
		$a_00_5 = {51 6f 74 20 52 65 63 6f 76 65 72 79 } //5 Qot Recovery
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*5+(#a_00_5  & 1)*5) >=9
 
}