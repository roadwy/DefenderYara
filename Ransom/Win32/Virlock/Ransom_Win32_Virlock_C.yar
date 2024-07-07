
rule Ransom_Win32_Virlock_C{
	meta:
		description = "Ransom:Win32/Virlock.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {e9 00 00 00 00 88 07 90 90 42 90 90 46 90 90 47 90 90 49 90 90 83 f9 00 90 90 0f 85 90 01 04 e9 90 01 04 81 ec 90 01 04 be 90 01 04 bf 90 01 04 e9 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}