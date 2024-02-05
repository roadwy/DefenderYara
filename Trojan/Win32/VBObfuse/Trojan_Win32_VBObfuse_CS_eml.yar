
rule Trojan_Win32_VBObfuse_CS_eml{
	meta:
		description = "Trojan:Win32/VBObfuse.CS!eml,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 14 18 81 fe fb 16 0d 9e } //01 00 
		$a_01_1 = {31 f2 81 fe 36 b1 0d 9e 75 68 } //00 00 
	condition:
		any of ($a_*)
 
}