
rule Misleading_Win32_SystemBooster{
	meta:
		description = "Misleading:Win32/SystemBooster,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 68 53 75 70 70 4e 75 6d } //1 PhSuppNum
		$a_01_1 = {77 00 77 00 77 00 2e 00 6f 00 6d 00 6e 00 69 00 74 00 77 00 65 00 61 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 www.omnitweak.com/
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 42 00 6f 00 6f 00 73 00 74 00 65 00 72 00 } //1 Software\SystemBooster
		$a_01_3 = {26 00 72 00 65 00 64 00 69 00 72 00 3d 00 2f 00 5b 00 50 00 52 00 4f 00 44 00 53 00 4d 00 4e 00 41 00 4d 00 45 00 5d 00 2f 00 70 00 75 00 72 00 63 00 68 00 61 00 73 00 65 00 2f 00 5b 00 53 00 59 00 53 00 56 00 45 00 4e 00 5d 00 2f 00 72 00 65 00 66 00 5f 00 5b 00 41 00 46 00 46 00 5d 00 2f 00 74 00 72 00 61 00 63 00 6b 00 5f 00 5b 00 54 00 52 00 4e 00 41 00 4d 00 45 00 5d 00 } //1 &redir=/[PRODSMNAME]/purchase/[SYSVEN]/ref_[AFF]/track_[TRNAME]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}