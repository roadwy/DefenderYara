
rule Trojan_Win32_StealC_CCHZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b c8 33 d2 8b c7 f7 f1 8b 45 f8 47 83 c4 04 8a 92 ?? ?? ?? ?? 32 14 03 88 13 83 ff 02 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}