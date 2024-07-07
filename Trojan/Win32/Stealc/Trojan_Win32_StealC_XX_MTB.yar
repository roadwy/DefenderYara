
rule Trojan_Win32_StealC_XX_MTB{
	meta:
		description = "Trojan:Win32/StealC.XX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 fa fe ff ff 30 04 33 83 ff 0f 75 25 6a 00 6a 00 6a 00 8d 8d fc f7 ff ff 51 6a 00 6a 00 ff 15 44 d0 40 00 ff 15 38 d0 40 00 6a 00 ff 15 60 d0 40 00 46 3b f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}