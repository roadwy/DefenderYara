
rule TrojanClicker_BAT_Ezbro_B{
	meta:
		description = "TrojanClicker:BAT/Ezbro.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {42 00 61 00 6e 00 6e 00 65 00 72 00 20 00 43 00 6c 00 69 00 63 00 6b 00 65 00 64 00 21 00 } //1 Banner Clicked!
		$a_01_1 = {77 00 65 00 62 00 71 00 3d 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 69 00 6e 00 64 00 65 00 72 00 2e 00 73 00 74 00 72 00 61 00 6e 00 67 00 6c 00 65 00 64 00 2e 00 6e 00 65 00 74 00 2f 00 3f 00 70 00 75 00 62 00 69 00 64 00 3d 00 } //1 webq=http://finder.strangled.net/?pubid=
		$a_01_2 = {53 00 65 00 61 00 72 00 63 00 68 00 69 00 6e 00 67 00 20 00 49 00 46 00 72 00 61 00 6d 00 65 00 20 00 6c 00 69 00 6e 00 6b 00 73 00 2e 00 2e 00 } //1 Searching IFrame links..
		$a_01_3 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 68 00 6f 00 6f 00 6b 00 20 00 52 00 65 00 66 00 65 00 72 00 65 00 72 00 20 00 6f 00 6e 00 20 00 49 00 45 00 38 00 } //1 Failed to hook Referer on IE8
		$a_01_4 = {57 00 69 00 6e 00 36 00 34 00 5f 00 38 00 36 00 78 00 4b 00 65 00 72 00 6e 00 65 00 6c 00 4d 00 75 00 74 00 65 00 78 00 31 00 } //1 Win64_86xKernelMutex1
		$a_01_5 = {63 00 73 00 49 00 57 00 65 00 62 00 42 00 72 00 6f 00 77 00 73 00 65 00 2e 00 41 00 53 00 63 00 72 00 69 00 70 00 74 00 } //1 csIWebBrowse.AScript
		$a_01_6 = {6d 00 69 00 6e 00 69 00 6f 00 6e 00 3d 00 74 00 72 00 75 00 65 00 20 00 63 00 6f 00 6e 00 73 00 74 00 61 00 6e 00 74 00 73 00 3d 00 7b 00 30 00 7d 00 } //1 minion=true constants={0}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=3
 
}