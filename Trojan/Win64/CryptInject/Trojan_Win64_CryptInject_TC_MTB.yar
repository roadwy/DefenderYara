
rule Trojan_Win64_CryptInject_TC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b c7 64 29 c6 0f b7 f6 49 8d 43 fc 41 0f b7 3c 78 66 42 89 7c 1d e8 41 0f b7 34 70 66 42 89 74 1d ea } //2
		$a_01_1 = {63 6d 64 6e 65 74 73 74 61 74 20 2d 61 6e 6f 20 7c 20 66 69 6e 64 73 74 72 20 3a } //1 cmdnetstat -ano | findstr :
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}