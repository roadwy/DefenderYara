
rule Trojan_Win32_Startpage_NA{
	meta:
		description = "Trojan:Win32/Startpage.NA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 70 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 38 38 30 38 2e 6e 65 74 2e 63 6e } //01 00  sp=http://www.8808.net.cn
		$a_01_1 = {31 2c 33 36 30 2e 63 6f 6d 0d 0a 31 2c 62 62 73 2e 33 36 30 2e 63 6e 0d 0a 31 2c 68 65 6c 70 2e 33 36 30 2e 63 6e 0d 0a 31 2c 33 39 33 32 2e 63 6f 6d 0d 0a 31 2c 32 35 34 38 2e 63 6e 0d 0a } //00 00 
	condition:
		any of ($a_*)
 
}