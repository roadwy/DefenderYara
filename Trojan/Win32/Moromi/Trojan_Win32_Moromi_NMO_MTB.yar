
rule Trojan_Win32_Moromi_NMO_MTB{
	meta:
		description = "Trojan:Win32/Moromi.NMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 6d 2f 64 61 74 61 6d 6f 64 65 6d } //02 00  comm/datamodem
		$a_01_1 = {6d 6f 72 6f 6d 69 65 2f 63 6f 6e 74 65 6e 74 73 2f 69 6e 64 65 78 2e 68 74 6d 6c } //02 00  moromie/contents/index.html
		$a_01_2 = {5c 53 59 53 54 45 4d 33 32 5c 52 41 53 5c 52 41 53 50 48 4f 4e 45 2e 50 42 4b } //02 00  \SYSTEM32\RAS\RASPHONE.PBK
		$a_01_3 = {4a 20 20 20 32 31 79 65 } //00 00  J   21ye
	condition:
		any of ($a_*)
 
}