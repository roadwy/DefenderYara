
rule Trojan_Win32_Zusy_MBHX_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 61 71 73 70 76 77 6f 2e 64 6c 6c 00 6a 6b 6e 77 61 70 75 66 6c 62 71 73 00 6b 61 72 70 76 6d 77 6c 68 69 79 6e 00 6c 76 67 73 78 70 7a 6f 74 00 7a 72 68 61 6b 63 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}