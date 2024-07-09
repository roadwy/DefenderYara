
rule Backdoor_Win32_Farfli_BT_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 02 8d 14 92 8b c1 2b c2 66 8b 54 84 04 66 31 14 4d [0-04] 41 3b ce 7c } //3
		$a_01_1 = {52 00 6d 00 65 00 70 00 72 00 60 00 70 00 66 00 58 00 48 00 68 00 61 00 71 00 6b 00 76 00 6e 00 64 00 77 00 58 00 52 00 68 00 6c 00 67 00 6b 00 72 00 72 00 5e 00 40 00 71 00 77 00 73 00 67 00 6d 00 70 00 53 00 64 00 70 00 70 00 6d 00 6a 00 6f 00 5e 00 51 00 71 00 6b 00 } //1 Rmepr`pfXHhaqkvndwXRhlgkrr^@qwsgmpSdppmjo^Qqk
		$a_01_2 = {45 00 6e 00 74 00 65 00 72 00 } //1 Enter
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}