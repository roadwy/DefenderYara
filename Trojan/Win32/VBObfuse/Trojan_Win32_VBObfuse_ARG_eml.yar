
rule Trojan_Win32_VBObfuse_ARG_eml{
	meta:
		description = "Trojan:Win32/VBObfuse.ARG!eml,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {8d 75 c0 8b fc a5 a5 a5 a5 8b 45 08 8b 00 ff 75 08 ff 90 b0 02 00 00 db e2 89 45 ac 83 7d ac 00 7d 1a } //01 00 
		$a_01_1 = {81 f7 1e 59 1f 12 } //01 00 
		$a_01_2 = {81 f6 b6 98 f2 e3 } //01 00 
		$a_01_3 = {81 f6 dc 30 79 9f } //01 00 
		$a_01_4 = {81 f7 6f 25 46 6a } //01 00 
		$a_01_5 = {81 f6 50 82 ea 2c } //00 00 
	condition:
		any of ($a_*)
 
}