
rule Spammer_Win32_Emotet_F{
	meta:
		description = "Spammer:Win32/Emotet.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 65 6d 61 69 6c 6e 61 6d 65 3e 3c 6e 61 6d 65 3e 3c 21 5b 43 44 41 54 41 5b 25 73 5d } //01 00  <emailname><name><![CDATA[%s]
		$a_00_1 = {7b 5c 2a 5c 68 74 6d 6c 74 61 67 } //02 00  {\*\htmltag
		$a_03_2 = {85 c0 74 24 81 be 90 01 02 00 00 c8 00 00 00 75 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}