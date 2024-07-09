
rule Trojan_BAT_Formbook_MP_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {06 0b 16 0c 2b 16 07 08 91 0d [0-02] 7e ?? ?? ?? 04 09 6f ?? ?? ?? 0a [0-03] 08 17 58 0c 08 07 8e 69 32 e4 7e ?? ?? ?? 04 6f ?? ?? ?? 0a [0-02] 2a } //1
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_4 = {50 69 6e 67 52 65 70 6c 79 } //1 PingReply
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}