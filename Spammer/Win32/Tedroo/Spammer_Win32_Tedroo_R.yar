
rule Spammer_Win32_Tedroo_R{
	meta:
		description = "Spammer:Win32/Tedroo.R,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b e8 85 ed 74 57 53 56 f0 35 6f 10 1d 20 6a 30 68 04 21 c0 10 55 ff d6 8b 1d 50 14 1f f8 7b 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}