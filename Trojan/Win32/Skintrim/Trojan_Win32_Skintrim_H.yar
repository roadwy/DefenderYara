
rule Trojan_Win32_Skintrim_H{
	meta:
		description = "Trojan:Win32/Skintrim.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_12_0 = {ff ff 53 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 61 c6 85 90 01 01 ff ff ff 72 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 4d c6 85 90 01 01 ff ff ff 43 90 00 01 } //00 6d 
		$a_ff_1 = {31 c6 85 90 01 02 ff ff 36 c6 85 90 01 02 ff ff 36 c6 } //85 90 
		$a_02_2 = {ff } //ff 39 
		$a_85_3 = {01 02 ff ff 37 c6 85 90 01 02 ff ff 35 c6 85 90 01 02 ff ff 32 c6 85 90 01 02 ff ff 37 c6 85 90 01 02 ff ff 30 c6 85 90 01 02 ff ff 32 c6 85 90 01 02 ff ff 39 c6 85 90 01 02 ff ff 30 c6 85 90 01 02 ff ff 33 c6 85 90 01 02 ff ff 34 90 00 00 00 80 10 00 00 36 bf 69 cc a5 7e bc 2b 4f 90 1b 7b 00 04 00 00 87 10 00 00 3a 2c a0 f0 6a 8f 40 f5 08 e8 6b 02 8e 39 01 00 5d 04 00 00 db 2c 02 80 5c 21 00 00 dc 2c 02 80 00 00 01 00 08 00 0b 00 ac 21 46 75 64 6e 69 6d 70 2e 41 00 00 01 40 05 82 70 00 04 00 87 10 00 00 7c fe 08 fd d1 69 6e e0 de 4a 25 c8 4c 2d 00 00 5d 04 00 00 dc 2c 02 80 5c 22 00 00 } //dd 2c 
	condition:
		any of ($a_*)
 
}