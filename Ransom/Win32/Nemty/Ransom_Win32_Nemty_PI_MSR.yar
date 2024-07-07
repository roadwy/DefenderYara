
rule Ransom_Win32_Nemty_PI_MSR{
	meta:
		description = "Ransom:Win32/Nemty.PI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {4e 45 4d 54 59 5f 50 52 49 56 41 54 45 } //1 NEMTY_PRIVATE
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 45 4d 54 59 5c } //1 Software\NEMTY\
		$a_01_2 = {72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6e 6f 20 26 20 77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 20 26 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 recoveryenabled no & wbadmin delete catalog -quiet & wmic shadowcopy delete
		$a_01_3 = {2d 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 2e 00 74 00 78 00 74 00 } //1 -DECRYPT.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}