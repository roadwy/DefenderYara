
rule Trojan_Win32_Kliper_A{
	meta:
		description = "Trojan:Win32/Kliper.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 4e 6f 4b 73 52 37 6a 63 54 54 75 66 67 72 76 68 36 7a 79 76 79 4a 6d 4c 32 7a 37 33 61 51 58 51 50 } //1 1NoKsR7jcTTufgrvh6zyvyJmL2z73aQXQP
		$a_01_1 = {2f 69 6e 66 6f 2e 70 68 70 3f 6b 65 79 3d } //1 /info.php?key=
		$a_01_2 = {5f 00 5f 00 4e 00 54 00 44 00 4c 00 4c 00 5f 00 43 00 4f 00 52 00 45 00 5f 00 5f 00 } //4 __NTDLL_CORE__
		$a_01_3 = {e1 0b 5e 0f 8f a8 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4+(#a_01_3  & 1)*1) >=7
 
}