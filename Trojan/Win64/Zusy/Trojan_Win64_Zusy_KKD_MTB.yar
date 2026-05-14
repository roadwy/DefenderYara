
rule Trojan_Win64_Zusy_KKD_MTB{
	meta:
		description = "Trojan:Win64/Zusy.KKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 f2 41 41 88 10 4d 8d 40 01 41 0f b6 10 84 d2 } //20
		$a_01_1 = {44 8b c8 41 c1 e9 1e 44 33 c8 41 69 c1 65 89 07 6c 41 03 c0 42 89 44 84 24 49 ff c0 49 81 f8 70 02 00 00 72 db } //10
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 2d 6e 20 32 20 31 32 37 2e 30 2e 30 2e 31 3e 6e 75 6c } //5 cmd.exe /c ping -n 2 127.0.0.1>nul
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}