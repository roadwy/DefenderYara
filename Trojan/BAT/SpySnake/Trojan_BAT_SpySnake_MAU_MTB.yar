
rule Trojan_BAT_SpySnake_MAU_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 55 b6 df 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c1 00 00 00 21 00 00 00 ea 00 00 00 17 07 00 00 f7 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {46 6f 72 6d 53 74 61 72 74 50 6f 73 69 74 69 6f 6e } //1 FormStartPosition
		$a_01_3 = {4d 61 69 6c 4d 65 73 73 61 67 65 } //1 MailMessage
		$a_01_4 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //1 NetworkCredential
		$a_01_5 = {61 64 64 5f 4d 6f 75 73 65 44 6f 77 6e } //1 add_MouseDown
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}