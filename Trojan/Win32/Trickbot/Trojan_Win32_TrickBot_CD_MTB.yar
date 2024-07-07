
rule Trojan_Win32_TrickBot_CD_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c2 8b 4d 90 01 01 03 4d 90 01 01 88 01 e9 90 09 1f 00 8b 55 90 01 01 03 55 90 01 01 33 c0 8a 02 8b 4d 90 01 01 03 4d 90 01 01 81 e1 ff 00 00 00 33 d2 8a 94 0d 90 00 } //1
		$a_02_1 = {81 e1 ff 00 00 00 89 4d 90 01 01 8b 55 90 01 01 33 c0 8a 84 15 90 01 04 89 45 90 01 01 8b 4d 90 01 01 8a 55 90 01 01 88 94 0d 90 01 04 8b 45 90 01 01 8a 4d 90 01 01 88 8c 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}