
rule Trojan_BAT_Stealer_ARR_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 07 17 58 0b 02 7b ?? ?? ?? ?? 07 1f 64 5a 02 } //10
		$a_81_1 = {2f 63 72 65 61 74 65 20 2f 74 6e 20 22 7b 30 7d 22 20 2f 74 72 20 22 5c 22 7b 31 7d 5c 22 20 2d 61 75 74 6f 22 20 2f 73 63 20 77 65 65 6b 6c 79 20 2f 64 20 7b 32 7d 20 2f 73 74 20 7b 33 7d 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 66 } //9 /create /tn "{0}" /tr "\"{1}\" -auto" /sc weekly /d {2} /st {3} /rl highest /f
		$a_81_2 = {5f 70 61 74 68 5f 69 6e 66 6f 2e 74 78 74 } //5 _path_info.txt
		$a_03_3 = {0a 06 16 72 ?? ?? ?? ?? a2 06 17 02 a2 06 18 04 a2 06 19 03 a2 06 } //6
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*9+(#a_81_2  & 1)*5+(#a_03_3  & 1)*6) >=30
 
}