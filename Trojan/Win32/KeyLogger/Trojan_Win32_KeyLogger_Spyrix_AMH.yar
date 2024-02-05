
rule Trojan_Win32_KeyLogger_Spyrix_AMH{
	meta:
		description = "Trojan:Win32/KeyLogger.Spyrix.AMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {4b 65 79 6c 6f 67 67 65 72 } //Keylogger  03 00 
		$a_80_1 = {53 70 79 72 69 78 } //Spyrix  03 00 
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 41 53 50 72 6f 74 65 63 74 5c 53 70 65 63 44 61 74 61 } //Software\ASProtect\SpecData  03 00 
		$a_80_3 = {47 68 6c 66 51 66 77 6b 70 77 65 63 46 } //GhlfQfwkpwecF  03 00 
		$a_80_4 = {5c 53 79 73 74 65 6d 5c 49 6f 73 75 62 73 79 73 5c 53 6d 61 72 74 76 73 64 2e 76 78 64 } //\System\Iosubsys\Smartvsd.vxd  03 00 
		$a_80_5 = {62 6c 61 63 6b 6c 69 73 74 65 64 20 6b 65 79 } //blacklisted key  03 00 
		$a_80_6 = {4c 61 73 74 4b 65 79 } //LastKey  00 00 
	condition:
		any of ($a_*)
 
}