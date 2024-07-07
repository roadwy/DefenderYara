
rule Trojan_Win32_Gandcrab_DHA_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff 15 90 01 04 8b 45 f4 03 45 fc 0f be 18 e8 90 01 04 33 d8 8b 4d f4 03 4d fc 88 19 eb 90 00 } //1
		$a_02_1 = {55 8b ec a1 90 01 04 69 c0 90 01 04 05 90 01 04 a3 90 01 04 a1 90 01 04 c1 e8 10 25 ff 7f 00 00 5d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}