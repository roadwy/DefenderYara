
rule Trojan_Win32_Alureon_DB{
	meta:
		description = "Trojan:Win32/Alureon.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0a 8b 11 8b 49 04 89 11 89 4a 04 6a 50 6a 00 50 e8 } //1
		$a_01_1 = {74 64 6c 33 64 65 73 6b } //1 tdl3desk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}