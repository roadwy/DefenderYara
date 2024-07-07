
rule Trojan_Win32_Azorult_AM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b cf c1 e1 04 03 8d 74 ff ff ff 3d a9 0f 00 00 75 0a } //3
		$a_01_1 = {8b 45 88 c1 e8 05 89 45 fc 8b 45 80 01 45 fc } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}