
rule Trojan_Win32_Filecoder_NFV_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.NFV!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 8b 4d dc 31 d2 f7 f1 8b 45 f4 01 d0 8b 4d e0 0f b6 09 0f b6 10 31 d1 8b 45 e4 88 08 } //5
		$a_01_1 = {81 f8 00 08 00 00 b8 00 00 00 00 0f 9f c0 85 c0 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}