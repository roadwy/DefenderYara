
rule Trojan_AndroidOS_LockerPin_A_MTB{
	meta:
		description = "Trojan:AndroidOS/LockerPin.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 80 11 00 62 08 ?? ?? 6e 10 ?? ?? 08 00 0c 08 07 84 07 18 01 39 07 1a 01 3b 48 0a 0a 0b 07 4b 01 3c 07 4d 21 dd b4 dc 48 0b 0b 0c b7 ba 8e aa 8d aa 4f 0a 08 09 d8 03 03 01 ?? ?? 07 38 07 59 6e 20 ?? ?? 98 00 0a 08 01 86 07 48 07 59 12 0a 01 6b } //2
		$a_00_1 = {63 6f 6d 2f 62 75 67 2f 63 65 73 68 69 2f 70 69 6e } //1 com/bug/ceshi/pin
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}