
rule Trojan_Win64_DriverInject_KG_MTB{
	meta:
		description = "Trojan:Win64/DriverInject.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 45 37 48 8b 0f e8 6a 01 00 00 ff c3 48 8d 7f 08 83 fb 17 72 ed 48 8b 4d 47 48 33 cc e8 5f 54 00 00 4c 8d 9c 24 f0 00 00 00 49 8b 5b 10 49 8b 7b } //1
		$a_01_1 = {0f be 0e 8b c3 48 33 c8 48 ff c6 0f b6 d1 48 8d 0d fc 47 00 00 c1 e8 08 8b 1c 91 33 d8 83 c7 ff 75 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}