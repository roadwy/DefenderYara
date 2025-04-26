
rule Trojan_Win32_Shiz_RG_MTB{
	meta:
		description = "Trojan:Win32/Shiz.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 cc d6 14 00 5a b9 50 49 2c 00 03 d1 52 33 db 53 ff 15 b0 c0 41 00 33 c0 a3 37 20 41 00 33 c9 c1 c1 06 49 2b c9 03 0d 28 20 41 00 41 c1 c1 05 81 e9 02 06 00 00 73 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}