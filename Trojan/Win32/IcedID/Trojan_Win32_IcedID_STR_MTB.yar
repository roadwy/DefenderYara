
rule Trojan_Win32_IcedID_STR_MTB{
	meta:
		description = "Trojan:Win32/IcedID.STR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a d1 33 d5 66 0f b6 6c 24 ?? 81 e2 ff 00 00 00 66 33 2c 55 c0 93 45 00 80 f9 7e 89 6c 24 1c 74 } //1
		$a_03_1 = {40 80 f1 20 8b 16 88 0c 10 8b 4c 24 ?? 40 47 3b f9 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}