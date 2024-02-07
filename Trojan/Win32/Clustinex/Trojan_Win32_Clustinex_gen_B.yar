
rule Trojan_Win32_Clustinex_gen_B{
	meta:
		description = "Trojan:Win32/Clustinex.gen!B,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 20 61 6c 74 3d 22 30 25 22 20 73 74 79 6c 65 3d 22 77 69 64 74 68 3a } //01 00  " alt="0%" style="width:
		$a_01_1 = {63 3a 2f 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 65 74 74 69 6e 67 73 2f 61 6c 6c 20 75 73 65 72 73 2f 61 70 70 6c 69 63 61 74 69 6f 6e 20 64 61 74 61 2f 74 65 6d 70 2f 68 74 6d 2f } //01 00  c:/documents and settings/all users/application data/temp/htm/
		$a_01_2 = {63 3a 5c 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 65 74 74 69 6e 67 73 5c 61 6c 6c 20 75 73 65 72 73 5c 61 70 70 6c 69 63 61 74 69 6f 6e 20 64 61 74 61 5c 74 65 6d 70 5c 68 74 6d 5c 6a 73 5c 62 72 61 6d 75 73 5c 6a 73 70 72 6f 67 72 65 73 73 62 61 72 68 61 6e 64 6c 65 72 2e 6a 73 } //01 00  c:\documents and settings\all users\application data\temp\htm\js\bramus\jsprogressbarhandler.js
		$a_01_3 = {63 3a 5c 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 73 65 74 74 69 6e 67 73 5c 61 6c 6c 20 75 73 65 72 73 5c 61 70 70 6c 69 63 61 74 69 6f 6e 20 64 61 74 61 5c 74 65 6d 70 5c 68 74 6d 5c 6a 73 5c 70 72 6f 74 6f 74 79 70 65 5c 70 72 6f 74 6f 74 79 70 65 2e 6a 73 } //01 00  c:\documents and settings\all users\application data\temp\htm\js\prototype\prototype.js
		$a_01_4 = {7b 33 34 61 37 31 35 61 30 2d 36 35 38 37 2d 31 31 64 30 2d 39 32 34 61 2d 30 30 32 30 61 66 63 37 61 63 34 64 7d } //00 00  {34a715a0-6587-11d0-924a-0020afc7ac4d}
	condition:
		any of ($a_*)
 
}