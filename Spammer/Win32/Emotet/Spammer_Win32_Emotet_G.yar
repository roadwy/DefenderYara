
rule Spammer_Win32_Emotet_G{
	meta:
		description = "Spammer:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 65 6d 61 69 6c 6e 61 6d 65 3e 3c 6e 61 6d 65 3e 3c 21 5b 43 44 41 54 41 5b 25 73 5d } //1 <emailname><name><![CDATA[%s]
		$a_01_1 = {7b 5c 2a 5c 68 74 6d 6c 74 61 67 } //1 {\*\htmltag
		$a_01_2 = {3c 00 4f 00 75 00 74 00 67 00 6f 00 69 00 6e 00 67 00 4c 00 6f 00 67 00 69 00 6e 00 4e 00 61 00 6d 00 65 00 3e 00 3c 00 21 00 5b 00 43 00 44 00 41 00 54 00 41 00 5b 00 25 00 73 00 5d 00 5d 00 3e 00 } //1 <OutgoingLoginName><![CDATA[%s]]>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}