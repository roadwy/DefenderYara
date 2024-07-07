
rule Trojan_Win32_Zusy_MBHP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 64 6b 72 68 6e 66 6c 64 2e 64 6c 6c 00 75 6a 72 6e 66 6a 64 6b 66 00 6b 66 6c 72 68 64 6e 62 6b 00 72 75 6a 67 66 6b 69 6a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}