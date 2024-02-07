
rule Trojan_Win32_Alureon_CG{
	meta:
		description = "Trojan:Win32/Alureon.CG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {76 65 72 3d 90 02 02 26 62 69 64 3d 25 73 26 61 69 64 3d 25 73 26 73 69 64 3d 25 73 26 71 3d 25 73 00 90 00 } //01 00 
		$a_01_1 = {00 3f 70 3d 00 26 70 3d 00 77 77 77 2e 62 69 6e 67 2e 63 6f 6d 00 } //01 00 
		$a_01_2 = {74 72 79 7b 76 61 72 20 78 3d 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 5f 61 22 29 3b 78 2e 68 72 65 66 3d 75 72 6c 3b 78 2e 63 6c 69 63 6b 28 29 7d 63 61 74 63 68 28 65 29 7b 74 72 79 7b 76 61 72 20 78 3d 64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 5f 66 22 29 3b } //01 00  try{var x=document.getElementById("_a");x.href=url;x.click()}catch(e){try{var x=document.getElementById("_f");
		$a_01_3 = {00 0d 0a 58 2d 4d 6f 7a 3a 20 70 72 65 66 65 74 63 68 0d 0a 00 0d 0a 75 73 65 72 2d 61 67 65 6e 74 3a 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}