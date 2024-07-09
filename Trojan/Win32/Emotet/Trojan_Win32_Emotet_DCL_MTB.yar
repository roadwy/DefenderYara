
rule Trojan_Win32_Emotet_DCL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 40 68 00 30 00 00 68 e0 07 00 00 6a 00 55 89 44 24 ?? 81 ee e0 07 00 00 ff d7 8b 4c 24 ?? 68 e0 07 00 00 03 ce 89 44 24 ?? 51 50 ff d3 83 c4 0c 6a 00 6a 40 68 00 30 00 00 56 6a 00 55 ff d7 } //2
		$a_02_1 = {56 6a 40 68 00 30 00 00 bf e0 07 00 00 57 56 ff 75 ?? 89 45 ?? 2b df ff 55 ?? 57 8b 7d ?? 8d 0c ?? 51 50 89 45 ?? ff 55 ?? 83 c4 0c 56 6a 40 68 00 30 00 00 53 56 ff 75 ?? ff 55 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}