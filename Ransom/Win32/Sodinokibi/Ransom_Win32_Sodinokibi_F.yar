
rule Ransom_Win32_Sodinokibi_F{
	meta:
		description = "Ransom:Win32/Sodinokibi.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2e 70 64 62 [0-20] 5c 74 6d 70 5f 90 0f 0a 00 5c 62 69 6e 5c [0-15] 2e 70 64 62 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}