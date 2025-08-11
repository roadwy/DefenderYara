
rule Trojan_Win32_Mint_AC_MTB{
	meta:
		description = "Trojan:Win32/Mint.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 89 08 50 45 43 6f 6d 70 61 63 74 32 00 00 4c 6a 00 8b 4f 0e a3 00 4c 6a 00 8b 09 62 8b 5d 40 e1 6d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}