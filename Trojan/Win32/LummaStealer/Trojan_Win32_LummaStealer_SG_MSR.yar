
rule Trojan_Win32_LummaStealer_SG_MSR{
	meta:
		description = "Trojan:Win32/LummaStealer.SG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {54 45 58 54 42 49 4e 2e 4e 45 54 2f 72 61 77 } //TEXTBIN.NET/raw  01 00 
		$a_80_1 = {56 4d 77 61 72 65 } //VMware  01 00 
		$a_80_2 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //processhacker  01 00 
		$a_80_3 = {6f 6c 6c 79 64 62 67 } //ollydbg  01 00 
		$a_80_4 = {63 75 63 6b 6f 6f } //cuckoo  01 00 
		$a_80_5 = {6e 65 74 6d 6f 6e } //netmon  01 00 
		$a_80_6 = {2f 56 45 52 59 53 49 4c 45 4e 54 20 2f 53 50 2d } ///VERYSILENT /SP-  00 00 
	condition:
		any of ($a_*)
 
}