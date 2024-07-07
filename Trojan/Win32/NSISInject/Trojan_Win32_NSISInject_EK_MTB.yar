
rule Trojan_Win32_NSISInject_EK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 50 57 ff 15 } //5
		$a_01_1 = {6a 40 68 00 30 00 00 50 56 ff 15 } //5
		$a_01_2 = {6a 40 68 00 30 00 00 50 53 ff 15 } //5
		$a_81_3 = {4e 53 49 53 20 45 72 72 6f 72 } //10 NSIS Error
		$a_03_4 = {8b 3c 24 40 eb 90 01 01 8b 04 24 ff e0 83 c4 0c 5e 5f 5b 5d c3 90 09 04 00 39 c5 74 90 00 } //1
		$a_03_5 = {8b 75 f0 40 eb 90 01 01 8b 45 f0 ff e0 81 f1 bd cb 00 00 4a 81 e3 2f e1 00 00 81 ea 51 57 00 00 c2 60 32 90 09 04 00 39 c3 74 90 00 } //1
		$a_03_6 = {40 39 c6 0f 85 90 01 02 ff ff 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_81_3  & 1)*10+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1) >=16
 
}