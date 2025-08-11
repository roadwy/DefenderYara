
rule Trojan_Win32_Mirage_SX_MTB{
	meta:
		description = "Trojan:Win32/Mirage.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f af c3 99 8b cf f7 f9 ff 4d f8 66 89 55 f4 75 df 33 db ff 45 08 39 7d 08 7c ca } //5
		$a_01_1 = {99 59 f7 f9 8b 44 24 1c 4b 66 89 2c 50 } //3
		$a_01_2 = {8d bd e8 fb ff ff f3 a5 6a 6b 33 c0 59 8d bd 44 fc ff ff f3 ab 8d 45 fc 89 5d fc } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}