
rule Trojan_Win32_Ninunarch_I{
	meta:
		description = "Trojan:Win32/Ninunarch.I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {3f 04 35 04 48 04 3d 04 3e 04 20 00 43 04 34 04 30 04 3b 04 51 04 3d 04 4b 04 21 00 0a 00 1d 04 } //4
		$a_01_1 = {62 74 6e 5f 75 6e 72 61 72 } //3 btn_unrar
		$a_01_2 = {21 00 6b 00 65 00 79 00 3d 00 25 00 4b 00 45 00 59 00 50 00 41 00 54 00 48 00 25 00 5c 00 6b 00 65 00 79 00 20 00 5b 00 78 00 6e 00 75 00 6d 00 5d 00 25 00 58 00 4e 00 55 00 4d 00 25 00 5b 00 2f 00 78 00 6e 00 75 00 6d 00 5d 00 5b 00 78 00 69 00 64 00 5d 00 25 00 58 00 49 00 44 00 25 00 5b 00 2f 00 78 00 69 00 64 00 5d 00 } //4 !key=%KEYPATH%\key [xnum]%XNUM%[/xnum][xid]%XID%[/xid]
		$a_01_3 = {68 72 65 66 20 3d 20 22 68 74 74 70 3a 2f 2f 73 6d 73 39 31 31 2e 72 75 2f 74 61 72 69 66 73 2e 70 68 70 } //4 href = "http://sms911.ru/tarifs.php
		$a_03_4 = {73 6d 73 74 65 78 74 3d 22 [0-05] 22 20 73 6d 73 6e 75 6d 3d 22 } //4
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_03_4  & 1)*4) >=11
 
}