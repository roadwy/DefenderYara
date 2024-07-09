
rule Trojan_Win32_FlyAgent_GMF_MTB{
	meta:
		description = "Trojan:Win32/FlyAgent.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? ca 56 00 89 35 ?? 93 56 00 8b fe 38 18 ?? ?? 8b f8 8d 45 f8 50 8d 45 fc } //10
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 33 36 30 73 6f 66 65 } //1 \Windows\CurrentVersion\Run\360sofe
		$a_01_2 = {40 4d 69 63 72 6f 73 6f 66 74 5c 43 6f 6e 66 69 67 2e 69 6e 69 } //1 @Microsoft\Config.ini
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}