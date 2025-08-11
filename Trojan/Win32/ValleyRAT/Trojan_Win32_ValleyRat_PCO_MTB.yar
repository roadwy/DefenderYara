
rule Trojan_Win32_ValleyRat_PCO_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 54 0d f4 0f b6 1c 38 2b da 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 41 88 1c 38 40 83 e1 07 3b c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}