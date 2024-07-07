
rule Trojan_Win64_BumbleBee_ULS_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.ULS!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 8b ce 89 6c 24 28 4c 8b c6 41 8b d7 89 44 24 20 48 8b cf 41 ff d4 } //1
		$a_01_1 = {43 72 65 61 74 65 45 76 65 6e 74 } //1 CreateEvent
		$a_01_2 = {51 4f 6d 50 48 68 39 57 4f } //1 QOmPHh9WO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}