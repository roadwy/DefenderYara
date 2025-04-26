
rule Ransom_Win32_Genasom_EO{
	meta:
		description = "Ransom:Win32/Genasom.EO,SIGNATURE_TYPE_PEHSTR_EXT,6f 00 6f 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 77 69 6e 6c 6f 63 6b 2e 70 64 62 } //100 \winlock.pdb
		$a_02_1 = {65 6e 74 65 72 (20 74 68 65|) 20 63 6f 64 65 } //10
		$a_00_2 = {2b 37 20 39 31 31 20 } //1 +7 911 
		$a_00_3 = {2b 37 20 39 38 31 20 } //1 +7 981 
	condition:
		((#a_00_0  & 1)*100+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=111
 
}