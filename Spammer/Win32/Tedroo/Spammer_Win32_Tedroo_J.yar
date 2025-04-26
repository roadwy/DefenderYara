
rule Spammer_Win32_Tedroo_J{
	meta:
		description = "Spammer:Win32/Tedroo.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 30 04 cb f8 4b 03 4a 75 e1 00 10 55 8b ec 51 51 8d 45 fc 50 ff 75 08 30 f8 50 6a 00 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}