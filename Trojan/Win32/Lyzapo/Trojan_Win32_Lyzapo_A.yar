
rule Trojan_Win32_Lyzapo_A{
	meta:
		description = "Trojan:Win32/Lyzapo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 20 bf 02 00 f3 ab d9 ee dd 5d d8 d9 ee dd 5d d0 66 ab aa } //1
		$a_03_1 = {83 c0 1e 50 ff 15 ?? ?? ?? 10 ff 75 fc ff 15 ?? ?? ?? 10 ff 45 f8 83 45 0c 04 8b 45 f8 3b 86 ?? ?? 00 00 0f 82 } //1
		$a_03_2 = {59 59 8b 75 0c c1 ee 0a 83 e6 01 e8 ?? ?? ?? 00 6a 05 99 59 f7 f9 } //1
		$a_01_3 = {ff 45 e8 39 5d e4 74 0e 8b 45 e8 6a 06 99 59 f7 f9 83 fa 01 75 2d } //1
		$a_01_4 = {8d 4d d8 6a 08 51 50 89 5d fc ff d6 8d 45 fc 53 50 8d 45 f8 6a 04 50 ff 75 f0 ff d6 83 7d fc 04 0f 85 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}