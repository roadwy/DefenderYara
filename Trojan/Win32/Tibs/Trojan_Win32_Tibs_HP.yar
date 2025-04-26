
rule Trojan_Win32_Tibs_HP{
	meta:
		description = "Trojan:Win32/Tibs.HP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 5a 85 d2 75 90 14 4a 41 52 51 [0-01] (29 d2 52|[0-05] 6a ?? 6a ?? 6a )} //1
		$a_01_1 = {03 4d 0c 03 4d 08 81 e9 } //1
		$a_03_2 = {03 4d 0c 03 4d 08 81 e9 01 ?? ?? ?? c9 90 09 06 00 (59 5a|5a 59) 85 d2 75 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=2
 
}