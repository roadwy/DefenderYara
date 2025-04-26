
rule Backdoor_Win32_CyberBill_A{
	meta:
		description = "Backdoor:Win32/CyberBill.A,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0d 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 6f 74 64 75 74 63 68 70 6f 72 6e 2e 6e 65 74 2f 63 62 2f 73 63 72 69 70 74 73 2f 67 65 74 41 64 64 72 65 73 73 46 72 6f 6d 49 50 2e 70 68 70 3f 77 6d 69 64 3d } //3 http://www.hotdutchporn.net/cb/scripts/getAddressFromIP.php?wmid=
		$a_01_1 = {43 79 62 65 72 62 69 6c 6c 44 69 61 6c 65 72 } //3 CyberbillDialer
		$a_01_2 = {55 52 4c 3a 43 79 62 65 72 62 69 6c 6c 20 50 72 6f 74 6f 63 6f 6c } //3 URL:Cyberbill Protocol
		$a_01_3 = {7e 7e 7e 7e 7e 7e 7e 7e 2e 68 74 6d } //3 ~~~~~~~~.htm
		$a_01_4 = {43 79 62 65 72 62 69 6c 6c 4e 47 } //2 CyberbillNG
		$a_01_5 = {64 69 61 6c 74 6f 6e 65 } //2 dialtone
		$a_01_6 = {25 63 6f 75 6e 74 72 79 2c 45 72 72 6f 72 55 72 6c 2c } //2 %country,ErrorUrl,
		$a_01_7 = {68 74 74 70 3a 2f 2f 64 69 61 6c 69 6e 2e 62 75 6e 6d 2e 64 65 2f } //1 http://dialin.bunm.de/
		$a_01_8 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 2d 63 61 73 68 2e 64 65 2f } //1 http://www.i-cash.de/
		$a_01_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 65 74 66 65 2e 6f 72 67 2f } //1 http://www.netfe.org/
		$a_01_10 = {68 74 74 70 3a 2f 2f 64 69 61 6c 69 6e 2e 63 6f 6d 6f 6e 6c 69 6e 65 2e 6e 65 74 2f } //1 http://dialin.comonline.net/
		$a_01_11 = {68 74 74 70 3a 2f 2f 64 69 61 6c 69 6e 2e 64 6e 69 62 76 2e 63 6f 6d 2f } //1 http://dialin.dnibv.com/
		$a_01_12 = {6d 6f 7a 69 6c 6c 61 77 69 6e 64 6f 77 63 6c 61 73 73 } //1 mozillawindowclass
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=10
 
}