
rule Trojan_Win32_Redline_EXP_MTB{
	meta:
		description = "Trojan:Win32/Redline.EXP!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 08 83 c5 70 c9 c2 08 00 } //1
		$a_01_1 = {50 8d 45 0c 50 e8 a8 f8 ff ff 8b 45 0c 33 45 fc 81 c3 47 86 c8 61 2b f8 ff 4d f8 0f 85 67 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}