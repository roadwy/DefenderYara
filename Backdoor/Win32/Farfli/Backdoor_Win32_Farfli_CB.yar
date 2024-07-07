
rule Backdoor_Win32_Farfli_CB{
	meta:
		description = "Backdoor:Win32/Farfli.CB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {33 db 36 0f be 14 28 3a d6 74 08 c1 cb 0d 03 da 40 eb ef 3b df 75 e7 } //2
		$a_01_1 = {68 74 74 70 3a 2f 2f 68 68 2e 72 6f 6f 74 65 72 2e 74 6b 2f 79 74 6a 2f 79 74 6a 2e 65 78 65 } //2 http://hh.rooter.tk/ytj/ytj.exe
		$a_03_2 = {95 bf 8e 4e 0e ec e8 90 01 02 ff ff 83 ec 04 83 2c 24 3c e9 90 00 } //1
		$a_03_3 = {89 34 24 bf 98 fe 8a 0e e8 90 01 01 ff ff ff 83 ec 04 83 2c 24 70 83 ec 64 bf 72 fa 4d db 90 00 } //1
		$a_03_4 = {bf 54 ca af 91 e8 90 01 01 fe ff ff 6a 04 68 00 10 00 00 6a 44 6a 00 ff d0 90 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}