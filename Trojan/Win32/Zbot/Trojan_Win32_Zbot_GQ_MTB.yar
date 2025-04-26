
rule Trojan_Win32_Zbot_GQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 72 28 6a 18 59 33 ff 33 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db 89 5d fc 8b 45 fc a3 b4 ab 40 00 5f 5e 5b 8b e5 5d c3 } //10
		$a_01_1 = {8b 45 fc 0f be 0c 10 8b 55 f4 0f be 82 98 a5 40 00 33 c1 8b 4d f4 88 81 98 a5 40 00 eb 88 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}