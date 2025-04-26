
rule TrojanDropper_Win32_Morix_A{
	meta:
		description = "TrojanDropper:Win32/Morix.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 08 32 4d f8 8b 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8 } //2
		$a_01_1 = {5c b3 cc d0 f2 5c c6 f4 b6 af 5c 33 36 30 74 72 61 79 2e 65 78 65 } //1
		$a_01_2 = {6c 6c 64 2e 64 6e 64 69 77 5c 73 25 } //1 lld.dndiw\s%
		$a_01_3 = {4e 47 53 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c a1 b8 bf aa ca bc a1 b9 b2 cb b5 a5 5c b3 cc d0 f2 5c c6 f4 b6 af } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}