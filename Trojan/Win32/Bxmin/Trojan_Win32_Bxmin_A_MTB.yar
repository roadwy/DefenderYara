
rule Trojan_Win32_Bxmin_A_MTB{
	meta:
		description = "Trojan:Win32/Bxmin.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 0f 80 f1 ?? 46 88 08 39 75 } //2
		$a_03_1 = {8a 0b 80 f1 ?? 46 88 08 39 75 } //2
		$a_03_2 = {8d 85 dc fe ff ff 50 ff 15 ?? 30 40 00 59 8b f0 8a 45 f3 53 8d 4d e0 88 45 e0 ff 15 ?? 30 40 00 56 e8 ?? 11 00 00 59 50 56 8d 4d e0 ff 15 ?? 30 40 00 8d 45 e0 68 ?? 40 40 00 50 89 5d fc ff 15 ?? 30 40 00 83 4d fc ff 59 59 88 45 f3 6a 01 8d 4d e0 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}