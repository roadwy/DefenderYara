
rule Trojan_Win32_Webot{
	meta:
		description = "Trojan:Win32/Webot,SIGNATURE_TYPE_PEHSTR,16 00 16 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 46 00 61 00 6b 00 75 00 6e 00 64 00 6f 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 42 00 61 00 73 00 69 00 63 00 5c 00 53 00 6f 00 75 00 72 00 63 00 65 00 73 00 5c 00 57 00 65 00 62 00 42 00 6f 00 74 00 5c 00 43 00 6f 00 64 00 65 00 } //10 \Users\Fakundo\Desktop\Visual Basic\Sources\WebBot\Code
		$a_01_1 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 Select * from AntiVirusProduct
		$a_01_2 = {2d 00 64 00 6f 00 73 00 2e 00 68 00 74 00 74 00 70 00 } //1 -dos.http
		$a_01_3 = {2d 00 64 00 6f 00 77 00 6e 00 65 00 78 00 65 00 } //1 -downexe
		$a_01_4 = {75 00 70 00 72 00 65 00 70 00 6f 00 72 00 74 00 73 00 2e 00 70 00 68 00 70 00 3f 00 26 00 61 00 63 00 63 00 3d 00 75 00 70 00 73 00 26 00 6e 00 69 00 63 00 6b 00 3d 00 } //10 upreports.php?&acc=ups&nick=
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=22
 
}