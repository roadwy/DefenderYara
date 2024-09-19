
rule Trojan_Win32_Floxif_YBZ_MTB{
	meta:
		description = "Trojan:Win32/Floxif.YBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cf f7 e7 c1 ea 04 6b c2 16 2b c8 2b ce 8a 44 0c 24 32 87 28 49 10 10 88 04 2f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}