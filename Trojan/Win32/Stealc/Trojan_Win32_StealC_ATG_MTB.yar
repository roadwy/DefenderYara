
rule Trojan_Win32_StealC_ATG_MTB{
	meta:
		description = "Trojan:Win32/StealC.ATG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c6 f7 f1 8b 45 0c 46 83 c4 04 8a 0c 02 8b 55 ?? 32 0c 3a 88 0f 3b 75 10 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}