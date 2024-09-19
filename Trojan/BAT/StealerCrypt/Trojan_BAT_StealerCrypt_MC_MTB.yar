
rule Trojan_BAT_StealerCrypt_MC_MTB{
	meta:
		description = "Trojan:BAT/StealerCrypt.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 d6 72 00 70 28 5f 00 00 2b 80 f7 07 00 04 20 07 00 00 00 38 5b ff ff ff 72 72 72 00 70 72 fa 72 00 70 28 60 00 00 2b 80 f2 07 00 04 20 03 00 00 00 38 3d ff ff ff 72 1c 73 00 70 72 28 73 00 70 28 61 00 00 2b 80 f8 07 00 04 20 06 00 00 00 38 1f ff ff ff 72 72 72 00 70 72 52 73 00 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}