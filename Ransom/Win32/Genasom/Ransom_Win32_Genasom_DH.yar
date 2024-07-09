
rule Ransom_Win32_Genasom_DH{
	meta:
		description = "Ransom:Win32/Genasom.DH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 72 75 00 00 00 00 48 54 54 50 2f 31 2e 30 00 [0-07] 2f 6c 6f 63 6b 65 72 2e 70 68 70 00 47 45 54 00 [0-05] 55 8b ec } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}