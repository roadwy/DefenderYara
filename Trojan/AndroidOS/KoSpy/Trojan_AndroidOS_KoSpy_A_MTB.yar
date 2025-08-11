
rule Trojan_AndroidOS_KoSpy_A_MTB{
	meta:
		description = "Trojan:AndroidOS/KoSpy.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 30 78 0f 06 08 55 60 1b 06 38 00 1c 00 70 10 cc 17 06 00 0a 00 39 00 16 00 6e 10 14 0c 06 00 0a 00 15 04 00 ff b5 40 15 04 00 01 33 40 04 00 01 30 28 02 } //1
		$a_01_1 = {3d 0a 18 00 54 db 24 06 52 bc f8 01 52 bb f9 01 b0 bc b1 ca 71 10 af 0b 0e 00 0a 0e 71 20 b1 70 ea 00 0a 0e 71 20 b0 0b 9e 00 0a 0e 01 3a 28 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}