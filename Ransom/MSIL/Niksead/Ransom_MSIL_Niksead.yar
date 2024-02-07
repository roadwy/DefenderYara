
rule Ransom_MSIL_Niksead{
	meta:
		description = "Ransom:MSIL/Niksead,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 44 35 37 38 33 42 43 46 31 45 39 30 30 32 42 43 30 30 41 44 35 42 38 33 41 39 35 45 44 36 45 34 45 42 42 34 41 44 35 } //02 00  DD5783BCF1E9002BC00AD5B83A95ED6E4EBB4AD5
		$a_01_1 = {52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //02 00  Ransomware.exe
		$a_01_2 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 61 00 72 00 6c 00 30 00 63 00 6b 00 2e 00 65 00 73 00 79 00 2e 00 65 00 73 00 2f 00 6c 00 6f 00 67 00 73 00 2f 00 } //02 00  ftp://darl0ck.esy.es/logs/
		$a_01_3 = {46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 73 00 74 00 6f 00 6c 00 6c 00 65 00 6e 00 } //02 00  Files has been stollen
		$a_01_4 = {5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 52 00 45 00 41 00 44 00 5f 00 49 00 54 00 2e 00 74 00 78 00 74 00 } //02 00  \Desktop\READ_IT.txt
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 64 2e 6b 6f 70 6f 72 75 73 68 6b 69 6e 5c 44 65 73 6b 74 6f 70 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //00 00  C:\Users\d.koporushkin\Desktop\WindowsFormsApp1\WindowsFormsApp1\obj\Debug\Ransomware.pdb
	condition:
		any of ($a_*)
 
}