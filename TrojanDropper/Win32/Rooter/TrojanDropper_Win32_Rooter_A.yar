
rule TrojanDropper_Win32_Rooter_A{
	meta:
		description = "TrojanDropper:Win32/Rooter.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {84 db 75 0b 6a 01 e8 90 01 04 84 db 74 f5 90 04 01 03 b8 2d bb 90 01 04 90 04 01 03 b8 2d bb 90 01 04 8a 90 02 05 32 90 02 05 32 90 02 05 88 90 02 05 80 fb ff 75 04 b3 01 eb 01 90 04 03 03 40 2d 4f 75 90 01 01 8d 45 ec ba 90 01 04 b9 00 01 00 00 e8 90 01 02 ff ff 8d 45 ec 8b 15 90 01 04 e8 90 01 02 ff ff 8b 55 ec b8 90 01 04 e8 90 01 02 ff ff ba 01 00 00 00 b8 90 01 04 e8 90 01 02 ff ff 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}