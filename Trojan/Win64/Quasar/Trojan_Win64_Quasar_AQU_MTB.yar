
rule Trojan_Win64_Quasar_AQU_MTB{
	meta:
		description = "Trojan:Win64/Quasar.AQU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 ff c0 8b c8 41 8a 04 06 32 02 48 ff c2 88 04 0e 45 3b c1 } //5
		$a_03_1 = {48 8b cf ff 15 ?? ?? ?? ?? 48 8d 15 3c 68 01 00 48 8b cf 48 89 05 72 ac 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 3d 68 01 00 48 8b cf 48 89 05 3b ac 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 3e 68 01 00 48 8b cf } //3
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 33 00 39 00 2e 00 31 00 38 00 30 00 2e 00 32 00 30 00 32 00 2e 00 32 00 32 00 37 00 3a 00 38 00 30 00 38 00 30 00 } //2 http://139.180.202.227:8080
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}