
rule Ransom_Win32_Ryuk_B{
	meta:
		description = "Ransom:Win32/Ryuk.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //5 RyukReadMe.html
		$a_01_1 = {2e 00 52 00 59 00 4b 00 } //5 .RYK
		$a_00_2 = {44 45 43 52 59 50 54 20 53 54 41 52 54 20 46 4f 52 20 33 30 20 53 45 43 4f 4e 44 53 2c 20 54 55 52 4e 20 4f 46 46 20 41 4c 4c 20 41 4e 54 49 56 49 52 55 53 20 53 4f 46 54 57 41 52 45 } //1 DECRYPT START FOR 30 SECONDS, TURN OFF ALL ANTIVIRUS SOFTWARE
		$a_00_3 = {43 3a 5c 6d 79 70 61 74 68 5c 73 6f 6d 65 70 61 74 68 5c 73 6f 6d 65 66 69 6c 65 2e 78 6c 73 } //1 C:\mypath\somepath\somefile.xls
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=10
 
}