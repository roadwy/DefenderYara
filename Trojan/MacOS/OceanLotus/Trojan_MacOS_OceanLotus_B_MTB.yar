
rule Trojan_MacOS_OceanLotus_B_MTB{
	meta:
		description = "Trojan:MacOS/OceanLotus.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 63 d2 41 8a 04 17 32 03 88 01 ff c2 44 39 f2 0f 4d d6 48 ff c3 48 ff c1 41 ff cd 75 e2 } //2
		$a_02_1 = {88 84 15 d0 fe ff ff 40 88 c7 40 00 ff 40 30 c7 88 c3 c0 fb ?? 80 e3 ?? 0f b6 c0 88 94 05 d0 fd ff ff 40 30 fb 48 ff c2 81 fa 00 ?? ?? ?? 88 d8 75 ce } //2
		$a_00_2 = {2f 74 6d 70 2f 63 72 75 6e 7a 69 70 2e 74 65 6d 70 2e 58 58 58 58 58 58 } //1 /tmp/crunzip.temp.XXXXXX
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1) >=3
 
}