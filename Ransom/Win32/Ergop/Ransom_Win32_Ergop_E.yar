
rule Ransom_Win32_Ergop_E{
	meta:
		description = "Ransom:Win32/Ergop.E,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 2e 2e 64 6f 63 00 52 65 61 64 5f 5f 5f 4d 45 2e 68 74 6d 6c 00 2e 2e 64 6f 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}