
rule Trojan_Win64_Vidar_MKE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 03 80 ?? ?? 42 88 0c 30 48 ff c0 48 83 f8 0c } //20
		$a_03_1 = {8a 4c 04 30 80 ?? ?? 88 0c 18 48 ff c0 48 83 f8 12 } //10
		$a_01_2 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6f 6b 69 65 73 } //3 \Network\Cookies
		$a_01_3 = {25 44 52 49 56 45 5f 52 45 4d 4f 56 41 42 4c 45 25 } //2 %DRIVE_REMOVABLE%
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=35
 
}