
rule Trojan_Win32_Ekstak_MBXC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MBXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a ff 68 f8 e4 4b 00 68 ec 80 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 } //1
		$a_01_1 = {55 8b ec 6a ff 68 58 89 65 00 68 90 7a 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}