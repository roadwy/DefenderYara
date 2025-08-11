
rule Trojan_Win32_Babar_AB_MTB{
	meta:
		description = "Trojan:Win32/Babar.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 45 43 6f 6d 70 61 63 74 32 00 16 a4 3a f5 7a a1 68 9d 1c 79 f6 48 4d 51 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}