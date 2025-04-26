
rule Ransom_Win32_ChortLocker_A{
	meta:
		description = "Ransom:Win32/ChortLocker.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 24 0f b6 14 02 31 d5 8b 54 24 10 95 88 04 3a 95 47 8b 6c 24 ?? 89 d0 8b 54 24 24 39 f9 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}