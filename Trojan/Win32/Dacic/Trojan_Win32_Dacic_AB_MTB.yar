
rule Trojan_Win32_Dacic_AB_MTB{
	meta:
		description = "Trojan:Win32/Dacic.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 8b 48 0c 8b 55 dc 8b 42 0c 8b 95 00 ff ff ff 8b b5 f8 fe ff ff 8a 0c 11 32 0c 30 8b 55 cc 8b 42 0c 8b 95 f0 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}