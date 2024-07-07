
rule Ransom_Win32_Rapid_A_MTB{
	meta:
		description = "Ransom:Win32/Rapid.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 45 4e 43 52 59 50 54 45 44 } //1 All your files have been ENCRYPTED
		$a_01_1 = {44 6f 20 79 6f 75 20 72 65 61 6c 6c 79 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 66 69 6c 65 73 3f } //1 Do you really want to restore your files?
		$a_01_2 = {57 72 69 74 65 20 74 6f 20 6f 75 72 20 65 6d 61 69 6c 20 2d 20 68 65 6c 70 40 77 69 7a 72 61 63 2e 63 6f 6d } //1 Write to our email - help@wizrac.com
		$a_01_3 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 /c vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}