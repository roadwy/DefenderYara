
rule Trojan_Win32_Neoreklami_MBYR_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.MBYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 77 6f 74 67 4b 48 5a 53 74 74 4f 62 49 7a 00 54 63 49 48 44 42 54 51 68 6c 48 4e 65 50 64 62 65 6a 5a 77 77 71 43 00 66 4e 44 47 4a 4a 59 4a 48 76 58 42 64 71 47 46 79 58 00 00 70 4f 78 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}