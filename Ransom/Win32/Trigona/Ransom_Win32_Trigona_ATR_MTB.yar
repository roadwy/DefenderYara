
rule Ransom_Win32_Trigona_ATR_MTB{
	meta:
		description = "Ransom:Win32/Trigona.ATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 89 45 ec 8d 45 ec 50 8d 45 f0 50 8d 45 f4 50 6a 00 6a 00 6a 01 68 30 01 00 00 8b 45 f8 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}