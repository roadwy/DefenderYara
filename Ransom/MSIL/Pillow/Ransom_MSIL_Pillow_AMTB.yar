
rule Ransom_MSIL_Pillow_AMTB{
	meta:
		description = "Ransom:MSIL/Pillow!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {49 20 61 6d 20 54 68 65 50 69 6c 6c 6f 77 20 52 61 6e 73 6f 6d 77 61 72 65 2c 20 63 72 65 61 74 65 64 20 62 79 20 55 64 6f 46 72 65 61 6b 2e } //I am ThePillow Ransomware, created by UdoFreak.  2
		$a_80_1 = {2e 50 49 4c 4c 4f 57 } //.PILLOW  2
		$a_80_2 = {5b 21 21 21 5d 20 45 58 54 52 45 4d 45 20 57 41 52 4e 49 4e 47 3a 20 54 48 49 53 20 50 52 4f 47 52 41 4d 20 45 4e 43 52 59 50 54 53 20 54 48 45 20 45 4e 54 49 52 45 20 44 49 53 4b 20 5b 21 21 21 5d } //[!!!] EXTREME WARNING: THIS PROGRAM ENCRYPTS THE ENTIRE DISK [!!!]  1
		$a_80_3 = {20 54 68 65 20 63 6f 6e 73 6f 6c 65 20 77 69 6e 64 6f 77 20 77 69 6c 6c 20 62 65 20 48 49 44 44 45 4e 20 64 75 72 69 6e 67 20 74 68 65 20 70 72 6f 63 65 73 73 2e } // The console window will be HIDDEN during the process.  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}