
rule Trojan_Win32_Zenpak_SPZR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {4f 79 64 68 65 63 74 72 50 61 61 65 68 61 61 72 69 73 6f 65 } //2 OydhectrPaaehaarisoe
		$a_01_1 = {6c 69 64 61 6f 6c 61 6e 69 61 39 36 2e 64 6c 6c } //1 lidaolania96.dll
		$a_01_2 = {4f 79 64 68 65 63 74 72 50 61 61 65 68 61 61 72 69 73 6f 65 } //1 OydhectrPaaehaarisoe
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}