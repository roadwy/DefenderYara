
rule Trojan_Win32_Dnschanger_AM{
	meta:
		description = "Trojan:Win32/Dnschanger.AM,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {2e 00 70 00 68 00 70 00 3f 00 75 00 73 00 65 00 72 00 3d 00 67 00 6f 00 6e 00 7a 00 69 00 6b 00 26 00 61 00 67 00 65 00 6e 00 74 00 3d 00 } //02 00  .php?user=gonzik&agent=
		$a_01_1 = {61 00 6c 00 70 00 68 00 61 00 5f 00 72 00 75 00 } //02 00  alpha_ru
		$a_01_2 = {66 00 6f 00 6f 00 64 00 6c 00 61 00 62 00 73 00 2e 00 72 00 75 00 } //01 00  foodlabs.ru
		$a_01_3 = {2e 00 44 00 4e 00 53 00 53 00 65 00 72 00 76 00 65 00 72 00 53 00 65 00 61 00 72 00 63 00 68 00 4f 00 72 00 64 00 65 00 72 00 } //01 00  .DNSServerSearchOrder
		$a_01_4 = {2e 00 53 00 65 00 74 00 44 00 4e 00 53 00 53 00 65 00 72 00 76 00 65 00 72 00 53 00 65 00 61 00 72 00 63 00 68 00 4f 00 72 00 64 00 65 00 72 00 } //00 00  .SetDNSServerSearchOrder
	condition:
		any of ($a_*)
 
}