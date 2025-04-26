
rule Trojan_Win32_Vidar_ASF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 f7 f1 8b 45 0c 8a 0c 02 8b 45 10 8b 55 08 03 c3 32 0c 02 88 08 ff 75 fc ff d7 ff 75 fc ff d7 } //2
		$a_01_1 = {74 2e 6d 65 2f 73 6f 6c 6f 6e 69 63 68 61 74 } //1 t.me/solonichat
		$a_01_2 = {41 75 74 6f 66 69 6c 6c 5c 25 73 5f 25 73 2e 74 78 74 } //1 Autofill\%s_%s.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}