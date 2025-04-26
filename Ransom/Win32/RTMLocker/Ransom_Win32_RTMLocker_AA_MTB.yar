
rule Ransom_Win32_RTMLocker_AA_MTB{
	meta:
		description = "Ransom:Win32/RTMLocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f8 40 73 21 8b 45 dc 41 8a 04 10 8b 55 f4 32 04 32 8b 55 e8 88 02 42 8b 45 f4 40 89 55 e8 89 45 f4 3b c7 72 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}