
rule Trojan_Win32_Wowsteal_Y{
	meta:
		description = "Trojan:Win32/Wowsteal.Y,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 43 4f 4d 53 50 45 43 00 2f 63 20 64 65 6c 20 00 20 3e 20 6e 75 6c 00 00 4f 70 65 6e 00 } //10
		$a_01_1 = {00 77 6f 6f 6f 6c 2e 64 61 74 } //10 眀潯汯搮瑡
		$a_01_2 = {5c 6d 61 70 5c 38 38 58 36 30 30 2e 6e 6d 70 } //10 \map\88X600.nmp
		$a_01_3 = {66 74 79 6f 75 } //1 ftyou
		$a_01_4 = {53 68 61 6e 64 61 } //1 Shanda
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=31
 
}