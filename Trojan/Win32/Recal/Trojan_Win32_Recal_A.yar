
rule Trojan_Win32_Recal_A{
	meta:
		description = "Trojan:Win32/Recal.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {3a 5c 52 45 43 59 43 4c 45 52 5c 63 90 04 02 02 66 74 5f 6d 6f 6e 2e 65 78 65 } //1
		$a_00_1 = {3a 00 5c 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6d 00 69 00 } //1 :\RECYCLER\desktop.imi
		$a_00_2 = {73 6d 69 6c 65 32 2e 6c 6f 67 } //1 smile2.log
		$a_00_3 = {73 6d 69 6c 65 2e 6c 6f 67 } //1 smile.log
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}