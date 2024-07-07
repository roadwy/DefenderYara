
rule Trojan_Win32_CryptAgent_SD_MTB{
	meta:
		description = "Trojan:Win32/CryptAgent.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 33 c0 b9 90 02 06 ba 90 02 06 90 02 06 85 c0 75 90 02 04 b8 01 00 00 00 eb 90 02 04 33 c0 90 02 06 8b 5d fc 03 de 73 90 02 06 e8 90 02 06 89 5d f8 90 02 06 85 c0 75 90 02 04 90 02 04 8a 1a 80 f3 46 88 5d f7 90 02 06 8b 5d f8 8b fb 8a 5d f7 88 1f 90 02 06 83 c6 01 73 90 00 } //1
		$a_00_1 = {2f 38 76 6c 62 59 77 51 48 32 79 48 4d 39 61 33 71 78 59 4d 6c 49 77 66 75 63 50 54 46 66 62 71 42 70 32 70 38 76 64 70 4e 48 57 32 5a 55 4f 41 } //1 /8vlbYwQH2yHM9a3qxYMlIwfucPTFfbqBp2p8vdpNHW2ZUOA
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}