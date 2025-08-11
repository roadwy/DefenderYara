
rule Trojan_Win32_Zusy_AHF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 45 e8 1c 8b 4d e0 8b 54 01 14 89 55 ac 6b 45 e8 1c 8b 4d e0 8b 54 01 10 89 55 88 8b 45 ac 25 ff ff 00 00 50 ff 15 } //2
		$a_03_1 = {8b 45 e0 8b 08 8b 51 10 89 55 90 90 6a 00 6a 00 8d 45 80 50 6a 00 68 ?? ?? ?? 10 8b 4d e0 51 ff 55 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}