
rule Backdoor_Win32_Ranfruct{
	meta:
		description = "Backdoor:Win32/Ranfruct,SIGNATURE_TYPE_PEHSTR,29 00 29 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 57 61 69 74 00 25 73 5c 25 73 2e 65 78 65 } //10
		$a_01_1 = {41 75 74 68 43 68 61 6e 67 65 50 61 73 73 77 6f 72 64 } //10 AuthChangePassword
		$a_01_2 = {45 6e 61 62 6c 65 41 75 74 6f 64 69 61 6c } //10 EnableAutodial
		$a_01_3 = {63 69 62 6c 63 69 6d 6d 64 69 67 68 64 69 6e 69 64 69 70 65 64 69 6a 69 64 69 61 69 63 69 6e 6d 62 69 62 65 63 } //10 ciblcimmdighdinidipedijidiaicinmbibec
		$a_01_4 = {66 72 65 73 68 6b 69 73 73 2e 6e 65 74 } //1 freshkiss.net
		$a_01_5 = {63 75 74 79 67 69 72 6c 73 2e 6e 65 74 } //1 cutygirls.net
		$a_01_6 = {67 2d 73 70 6f 74 2e 74 6f 2f 66 72 65 65 } //1 g-spot.to/free
		$a_01_7 = {73 6f 6d 65 74 68 69 6e 67 70 69 6e 6b 2e 63 6f 6d } //1 somethingpink.com
		$a_01_8 = {69 69 6a 34 75 2e 6f 72 2e 6a 70 } //1 iij4u.or.jp
		$a_01_9 = {73 75 6b 65 62 65 6c 61 6e 64 2e 6e 65 74 2f 61 64 } //1 sukebeland.net/ad
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=41
 
}