
rule Ransom_Win32_Genasom_Q{
	meta:
		description = "Ransom:Win32/Genasom.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 00 33 00 36 00 31 00 36 00 } //1 13616
		$a_01_1 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_01_2 = {6c 00 6f 00 63 00 6b 00 65 00 72 00 20 00 2d 00 20 00 6e 00 65 00 77 00 5c 00 74 00 6f 00 53 00 45 00 4e 00 44 00 5c 00 66 00 6f 00 72 00 6d 00 2e 00 76 00 62 00 70 00 } //1 locker - new\toSEND\form.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}