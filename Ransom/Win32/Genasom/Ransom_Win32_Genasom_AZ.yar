
rule Ransom_Win32_Genasom_AZ{
	meta:
		description = "Ransom:Win32/Genasom.AZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 63 72 00 65 65 6e 2e 6a 70 67 [0-06] 45 78 70 6c 6f 72 65 00 72 20 68 74 74 70 3a 2f 00 2f [0-10] 2e 50 6e 65 74 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}