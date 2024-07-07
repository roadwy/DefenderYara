
rule Virus_Win32_Expiro_DB_MTB{
	meta:
		description = "Virus:Win32/Expiro.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f1 8b 0a 85 c8 81 f1 90 01 04 3b f1 89 0e 49 48 48 81 c6 04 00 00 00 48 48 81 c2 04 00 00 00 85 c0 75 db 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}