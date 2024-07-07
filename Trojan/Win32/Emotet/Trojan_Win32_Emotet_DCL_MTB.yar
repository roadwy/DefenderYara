
rule Trojan_Win32_Emotet_DCL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 40 68 00 30 00 00 68 e0 07 00 00 6a 00 55 89 44 24 90 01 01 81 ee e0 07 00 00 ff d7 8b 4c 24 90 01 01 68 e0 07 00 00 03 ce 89 44 24 90 01 01 51 50 ff d3 83 c4 0c 6a 00 6a 40 68 00 30 00 00 56 6a 00 55 ff d7 90 00 } //2
		$a_02_1 = {56 6a 40 68 00 30 00 00 bf e0 07 00 00 57 56 ff 75 90 01 01 89 45 90 01 01 2b df ff 55 90 01 01 57 8b 7d 90 01 01 8d 0c 90 01 01 51 50 89 45 90 01 01 ff 55 90 01 01 83 c4 0c 56 6a 40 68 00 30 00 00 53 56 ff 75 90 01 01 ff 55 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}