
rule Ransom_Win32_Babuk_MK_MTB{
	meta:
		description = "Ransom:Win32/Babuk.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {56 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //Vssadmin.exe delete shadows /all /quiet  01 00 
		$a_80_1 = {2e 62 61 62 79 6b } //.babyk  01 00 
		$a_80_2 = {52 61 6e 73 6f 6d 77 61 72 65 } //Ransomware  01 00 
		$a_80_3 = {48 6f 77 20 54 6f 20 52 65 73 74 6f 72 65 20 59 6f 75 72 20 46 69 6c 65 73 2e 74 78 74 } //How To Restore Your Files.txt  00 00 
	condition:
		any of ($a_*)
 
}