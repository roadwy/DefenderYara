
rule Trojan_Win32_Swisyn_ASL_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 00 68 ec ?? 9a 00 50 e8 3a 2a 00 00 83 c4 08 8d 4c 24 00 6a 10 68 ac ?? 9a 00 51 6a 00 ff 15 } //2
		$a_03_1 = {51 53 68 4b 10 00 00 6a 78 56 89 44 24 78 ff d7 50 ff d5 85 c0 75 18 6a 30 68 ac ?? 9a 00 68 80 ?? 9a 00 56 ff 15 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}