
rule Trojan_WinNT_Rootkitdrv_B{
	meta:
		description = "Trojan:WinNT/Rootkitdrv.B,SIGNATURE_TYPE_PEHSTR,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c4 50 b8 7b 1d 80 7c ff d0 } //10
		$a_01_1 = {49 6e 6a 65 63 74 45 79 65 } //1 InjectEye
		$a_01_2 = {49 6e 6a 65 63 74 20 6c 6f 61 64 65 72 20 6f 6b } //1 Inject loader ok
		$a_01_3 = {48 6f 6f 6b 20 6f 6b 21 } //1 Hook ok!
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}