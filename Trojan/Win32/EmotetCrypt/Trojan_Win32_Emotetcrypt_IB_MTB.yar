
rule Trojan_Win32_Emotetcrypt_IB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bd 90 01 04 f7 fd 8b 44 24 54 8b 6c 24 18 83 c5 01 89 6c 24 18 03 d7 03 d6 0f b6 14 02 8b 44 24 20 30 54 28 ff 3b 6c 24 5c 0f 82 90 00 } //1
		$a_81_1 = {70 21 63 21 58 38 3c 30 61 69 52 31 3e 66 6b 64 79 6d 45 3c 58 21 21 78 66 64 74 5a 3f 3c 2a 26 6e 4a 78 52 5a 7a 39 56 6f 79 21 26 71 33 2a 49 54 6b 46 35 37 72 40 5f 45 61 43 4c 7a } //1 p!c!X8<0aiR1>fkdymE<X!!xfdtZ?<*&nJxRZz9Voy!&q3*ITkF57r@_EaCLz
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}