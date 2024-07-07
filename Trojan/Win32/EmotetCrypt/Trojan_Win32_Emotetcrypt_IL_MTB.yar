
rule Trojan_Win32_Emotetcrypt_IL_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 03 0d 90 01 04 03 0d 90 01 04 a1 90 01 04 0f af 05 90 01 04 2b c8 a1 90 01 04 0f af 05 90 01 04 03 45 08 0f b6 0c 08 8b 45 0c 0f b6 14 10 33 d1 a1 90 01 04 0f af 05 90 01 04 8b 4d f4 2b 0d 90 01 04 03 0d 90 01 04 03 45 0c 88 14 08 90 00 } //1
		$a_81_1 = {70 66 79 28 6f 74 6c 24 4a 30 79 5f 6d 41 31 71 44 43 32 7a 3e 4f 70 45 62 61 56 62 49 31 65 36 2b 23 70 71 4d 75 6a 5f 6e 6d 47 5e 2b 26 26 48 2a 46 78 37 78 24 5e 6d 36 5f 38 36 66 4e 79 48 58 6a 24 64 66 34 62 3e 63 67 5f 25 6d 28 68 30 79 46 3e 25 58 59 73 51 56 39 28 78 40 63 } //1 pfy(otl$J0y_mA1qDC2z>OpEbaVbI1e6+#pqMuj_nmG^+&&H*Fx7x$^m6_86fNyHXj$df4b>cg_%m(h0yF>%XYsQV9(x@c
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}