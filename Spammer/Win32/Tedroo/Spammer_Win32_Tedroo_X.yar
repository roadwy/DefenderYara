
rule Spammer_Win32_Tedroo_X{
	meta:
		description = "Spammer:Win32/Tedroo.X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 30 04 cb f8 4b 03 4a 75 e1 03 ?? 81 ec 10 01 00 00 56 57 be ?? ?? ?? f4 a5 a5 66 a5 be ?? ?? 58 56 53 e8 ?? ?? c8 85 c0 59 59 74 5b 33 c0 8a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}