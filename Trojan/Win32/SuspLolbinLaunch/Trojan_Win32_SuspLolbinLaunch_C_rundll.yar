
rule Trojan_Win32_SuspLolbinLaunch_C_rundll{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.C!rundll,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 90 02 40 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 90 02 40 5f 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 90 00 } //1
		$a_00_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 2e 00 63 00 70 00 6c 00 } //65535 Windows\System32\Firewall.cpl
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*65535) >=1
 
}