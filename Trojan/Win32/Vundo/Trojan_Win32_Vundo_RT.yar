
rule Trojan_Win32_Vundo_RT{
	meta:
		description = "Trojan:Win32/Vundo.RT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 7d fc 3c 21 2d 2d 74 } //1
		$a_01_1 = {81 3c 10 8b ff 55 8b 74 0d 41 83 f9 12 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}