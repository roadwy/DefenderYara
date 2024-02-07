
rule Ransom_Win32_Getawa_B_MTB{
	meta:
		description = "Ransom:Win32/Getawa.B!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 2f 71 20 2f 73 20 2f 66 20 73 79 73 74 65 6d 40 69 6e 74 65 72 72 75 70 74 73 2e 65 78 65 } //01 00  del /q /s /f system@interrupts.exe
		$a_01_1 = {6d 64 20 25 77 69 6e 64 69 72 25 5c 53 79 73 57 4f 57 36 34 5c 6a 61 76 61 5c 6a 61 77 61 } //01 00  md %windir%\SysWOW64\java\jawa
		$a_01_2 = {64 65 6c 20 25 77 69 6e 64 69 72 25 5c 73 79 73 74 65 6d 33 32 5c 73 75 70 65 72 64 61 74 76 70 6e 2e 65 78 65 } //01 00  del %windir%\system32\superdatvpn.exe
		$a_01_3 = {25 74 65 6d 70 25 5c 72 61 72 63 65 6b 2e 74 78 74 } //00 00  %temp%\rarcek.txt
	condition:
		any of ($a_*)
 
}