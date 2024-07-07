
rule Backdoor_Win32_Farfli_GZ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 f0 d2 e1 8a 45 00 80 d9 1b 10 e9 8a 4d 02 } //10
		$a_01_1 = {73 76 63 68 73 6f 74 2e 65 78 65 } //1 svchsot.exe
		$a_01_2 = {68 6f 73 74 31 32 33 2e 7a 7a 2e 61 6d } //1 host123.zz.am
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}