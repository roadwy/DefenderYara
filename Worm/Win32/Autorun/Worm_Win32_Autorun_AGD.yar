
rule Worm_Win32_Autorun_AGD{
	meta:
		description = "Worm:Win32/Autorun.AGD,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 52 45 43 59 43 4c 45 52 00 00 00 2e 3a 3a 5b 55 73 62 5d 3a 3a 2e 20 49 6e 66 65 63 74 65 64 20 64 72 69 76 65 3a 20 25 73 } //2
		$a_01_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 \autorun.inf
		$a_01_2 = {48 4f 53 54 3a 20 77 77 77 2e 61 64 6f 62 65 2e 63 6f 6d 2e 63 6e } //1 HOST: www.adobe.com.cn
		$a_01_3 = {64 65 6c 20 25 25 30 } //1 del %%0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}