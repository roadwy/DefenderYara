
rule Trojan_Win64_CryptInject_AW_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 4c 8b 04 25 30 00 00 00 33 ff 45 32 f6 45 32 ed 44 8b ff 44 8d 4f 01 49 8b 50 60 48 8b 42 30 48 89 44 24 20 } //2
		$a_01_1 = {44 69 73 61 62 6c 65 72 20 6d 65 6d 20 73 74 61 72 74 } //1 Disabler mem start
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}