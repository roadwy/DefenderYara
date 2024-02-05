
rule Trojan_Win32_Zbot_DR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 5d fe 8a c8 8a 45 ff 8a d4 80 f1 da 80 f2 79 80 f3 31 34 38 80 f9 e9 75 0d 80 fa 40 75 08 84 db 75 04 84 c0 74 0d 8b 45 fc 03 c6 89 45 fc 83 f8 ff 76 cc } //01 00 
		$a_01_1 = {83 c4 0c 8d 46 1c 2b ce bf 01 01 00 00 8a 14 01 88 10 40 4f 75 f7 8d 86 1d 01 00 00 be 00 01 00 00 8a 14 08 88 10 40 4e 75 f7 } //00 00 
	condition:
		any of ($a_*)
 
}