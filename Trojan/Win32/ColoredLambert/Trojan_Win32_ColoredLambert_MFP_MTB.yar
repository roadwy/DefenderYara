
rule Trojan_Win32_ColoredLambert_MFP_MTB{
	meta:
		description = "Trojan:Win32/ColoredLambert.MFP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ef 05 8b d8 c1 e3 04 33 fb 8b 5d fc 83 e3 03 03 3c 9e 8b 5d fc 81 6d fc 47 86 c8 61 33 d8 03 d9 8d 0c 3b 8b f9 c1 ef 05 8b d9 c1 e3 04 33 fb 8b 5d fc c1 eb 0b 83 e3 03 03 3c 9e 8b 5d fc 33 d9 03 d8 8d 04 3b 39 55 fc 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}