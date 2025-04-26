
rule Trojan_Win32_Blackmon_A{
	meta:
		description = "Trojan:Win32/Blackmon.A,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 77 65 6b 68 73 67 } //1 awekhsg
		$a_01_1 = {53 61 6e 64 62 6f 78 69 61 2e 69 6e 69 } //1 Sandboxia.ini
		$a_01_2 = {35 39 36 32 35 37 44 44 39 33 46 33 30 39 35 36 41 30 35 37 41 32 39 46 33 41 39 39 } //1 596257DD93F30956A057A29F3A99
		$a_01_3 = {62 6c 61 63 6b 6d 6f 6f 6e } //1 blackmoon
		$a_01_4 = {2f 54 65 6c 78 63 6c 73 6a 63 67 7a 68 } //1 /Telxclsjcgzh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}