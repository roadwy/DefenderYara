
rule Worm_Win32_PictLuv_AYA_MTB{
	meta:
		description = "Worm:Win32/PictLuv.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_00_0 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //2 aaa_TouchMeNot_.txt
		$a_00_1 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 33 00 32 00 5c 00 68 00 69 00 74 00 2e 00 65 00 78 00 65 00 } //2 WINDOWS\SYSTEM32\hit.exe
		$a_01_2 = {77 77 77 2e 6c 6f 76 65 2e 67 72 65 65 74 69 6e 67 73 2e 63 6f 6d } //1 www.love.greetings.com
		$a_01_3 = {77 77 77 2e 6e 65 74 5f 73 70 65 65 64 2e 74 78 74 2e 63 6f 6d } //1 www.net_speed.txt.com
		$a_01_4 = {77 77 77 2e 6c 6f 76 65 63 61 6c 63 2e 74 78 74 2e 63 6f 6d } //1 www.lovecalc.txt.com
		$a_01_5 = {77 77 77 2e 70 69 63 74 75 72 65 2e 61 64 76 61 6e 69 2e 74 65 68 65 6c 6b 61 2e 63 6f 6d } //1 www.picture.advani.tehelka.com
		$a_01_6 = {46 69 6c 65 20 63 75 72 72 65 70 74 65 64 } //1 File currepted
		$a_01_7 = {54 68 69 73 20 74 65 78 74 20 66 69 6c 65 20 63 6f 6e 74 61 69 6e 73 20 73 6f 6d 65 20 63 61 6c 63 75 6c 61 74 69 6f 6e 73 20 72 65 6c 61 74 65 64 20 74 6f 20 73 70 65 65 64 20 6f 66 20 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 2c 20 76 65 72 69 66 79 20 69 74 } //1 This text file contains some calculations related to speed of net connections, verify it
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}