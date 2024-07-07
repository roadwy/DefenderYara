
rule Trojan_Win32_Guloader_CF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0c 00 00 "
		
	strings :
		$a_01_0 = {61 6c 61 62 61 73 74 66 61 62 72 69 6b 6b 65 72 5c 74 65 6c 65 69 6e 66 72 61 73 74 72 75 6b 74 75 72 65 6e 2e 69 6e 69 } //1 alabastfabrikker\teleinfrastrukturen.ini
		$a_01_1 = {63 3a 5c 74 65 6d 70 5c 61 2e 74 78 74 } //1 c:\temp\a.txt
		$a_01_2 = {53 61 6e 64 62 6f 78 65 73 35 39 5c 76 69 73 6d 75 74 73 2e 69 6e 69 } //1 Sandboxes59\vismuts.ini
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 67 61 6e 67 65 73 74 79 6b 6b 65 72 6e 65 73 } //1 Software\gangestykkernes
		$a_01_4 = {64 69 67 69 74 61 6c 75 72 65 6e 65 73 2e 74 72 61 } //1 digitalurenes.tra
		$a_01_5 = {54 72 61 6e 73 69 74 65 64 31 30 36 2e 48 6f 72 } //1 Transited106.Hor
		$a_01_6 = {53 6f 66 74 77 61 72 65 5c 61 6d 74 73 73 6b 61 74 74 65 69 6e 73 70 65 6b 74 6f 72 61 74 5c 6d 65 6e 6e 65 73 6b 65 } //1 Software\amtsskatteinspektorat\menneske
		$a_01_7 = {66 69 6c 6c 69 70 69 6e 73 6b 65 5c 55 62 65 73 6d 69 74 74 65 64 65 32 31 30 2e 64 6c 6c } //1 fillipinske\Ubesmittede210.dll
		$a_01_8 = {68 65 72 73 65 72 5c 62 65 68 6f 76 73 75 6e 64 65 72 73 67 65 6c 73 65 72 6e 65 73 2e 69 6e 69 } //1 herser\behovsundersgelsernes.ini
		$a_01_9 = {53 6f 66 74 77 61 72 65 5c 75 64 6b 6c 64 6e 69 6e 67 65 6e 5c 74 72 69 63 6b 6c 69 65 73 74 } //1 Software\udkldningen\trickliest
		$a_01_10 = {75 6e 66 69 62 65 72 65 64 25 5c 6b 6c 61 73 6b 65 6e 65 73 5c 74 61 77 6b 65 65 2e 42 61 61 } //1 unfibered%\klaskenes\tawkee.Baa
		$a_01_11 = {67 65 6e 6e 65 6d 61 72 62 65 6a 64 65 6c 73 65 72 2e 62 73 73 } //1 gennemarbejdelser.bss
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=6
 
}