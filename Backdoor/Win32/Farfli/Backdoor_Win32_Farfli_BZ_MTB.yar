
rule Backdoor_Win32_Farfli_BZ_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 81 c2 d1 00 00 00 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8 8b 45 fc 99 b9 03 00 00 00 f7 f9 85 d2 75 } //2
		$a_01_1 = {32 31 31 2e 31 35 32 2e 31 34 37 2e 39 37 2f 62 62 73 } //1 211.152.147.97/bbs
		$a_01_2 = {77 77 77 2e 73 61 72 61 68 63 6c 75 62 2e 63 6f 6d } //1 www.sarahclub.com
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}