
rule TrojanClicker_Win32_Agent_MZA{
	meta:
		description = "TrojanClicker:Win32/Agent.MZA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 44 65 62 75 67 73 2e 69 6e 66 } //1 \Debugs.inf
		$a_01_1 = {25 73 5c 63 63 6c 69 63 6b 2e 65 78 65 } //1 %s\cclick.exe
		$a_01_2 = {2e 30 32 31 61 64 73 2e 63 6f 6d } //1 .021ads.com
		$a_01_3 = {2e 31 32 35 38 30 62 6a 2e 63 6f 6d 2f } //1 .12580bj.com/
		$a_01_4 = {25 73 3f 6d 61 63 3d 25 73 26 76 65 72 3d 25 73 26 4f 73 3d 25 73 26 46 69 6c 65 4e 75 6d 3d 25 64 26 4e 75 6d 3d } //1 %s?mac=%s&ver=%s&Os=%s&FileNum=%d&Num=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}