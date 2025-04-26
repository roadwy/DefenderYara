
rule Trojan_Win32_Fakovid_PB_MSR{
	meta:
		description = "Trojan:Win32/Fakovid.PB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 61 6f 6c 6e 77 6f 64 3d 74 72 6f 70 78 65 26 [0-24] 3d 64 69 3f 63 75 2f 30 2f 75 2f 6d 6f 63 2e 65 6c 67 6f 6f 67 2e 65 76 69 72 64 2f 2f 3a 73 70 74 74 68 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}