
rule Trojan_Win32_Lukicsel_L{
	meta:
		description = "Trojan:Win32/Lukicsel.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 fb 1d 75 ?? c7 06 9a 02 00 00 eb } //1
		$a_03_1 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}