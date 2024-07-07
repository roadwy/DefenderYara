
rule Trojan_Win32_Finkmilt_B_dll{
	meta:
		description = "Trojan:Win32/Finkmilt.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 64 72 2e 65 78 65 00 50 72 6b 74 00 } //1
		$a_01_1 = {8b d2 90 8b d2 8b d2 68 3f 00 0f 00 8b d2 90 6a 00 8b d2 90 6a 00 90 ff d0 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}