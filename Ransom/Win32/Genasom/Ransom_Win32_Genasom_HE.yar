
rule Ransom_Win32_Genasom_HE{
	meta:
		description = "Ransom:Win32/Genasom.HE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {45 f4 eb 02 eb 10 48 c1 e8 0f c1 e0 0f 0f b7 08 81 e9 4d 5a 00 00 0b c9 75 01 } //1
		$a_5c_1 = {69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 5c 52 } //11776 ilence_lock_bot\R
	condition:
		((#a_11_0  & 1)*1+(#a_5c_1  & 1)*11776) >=2
 
}