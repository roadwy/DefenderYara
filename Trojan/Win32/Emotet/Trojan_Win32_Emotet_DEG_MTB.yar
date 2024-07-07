
rule Trojan_Win32_Emotet_DEG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 44 24 18 8b 4c 24 24 40 89 44 24 18 8a 54 14 28 30 54 01 ff 90 00 } //1
		$a_81_1 = {70 72 38 76 68 4f 77 5a 61 37 48 74 34 46 4b 66 39 39 6a 39 58 74 6f 70 5a 5a 4f 4f 76 } //1 pr8vhOwZa7Ht4FKf99j9XtopZZOOv
		$a_02_2 = {03 c1 99 b9 90 01 04 f7 f9 8b 4c 24 14 8b 44 24 18 83 c1 01 89 4c 24 14 8a 54 14 24 30 54 08 ff 90 00 } //1
		$a_81_3 = {39 6a 6b 35 59 50 72 52 30 75 6f 71 76 4f 71 47 35 53 7a 6e 7a 32 56 71 77 4d 6b 54 66 41 64 34 } //1 9jk5YPrR0uoqvOqG5Sznz2VqwMkTfAd4
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_02_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}