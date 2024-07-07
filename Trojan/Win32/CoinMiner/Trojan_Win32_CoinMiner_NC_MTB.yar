
rule Trojan_Win32_CoinMiner_NC_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 85 f6 75 08 6a 90 01 01 e8 36 b9 ff ff 59 89 35 90 01 04 c7 05 40 05 a6 00 90 01 04 8d 86 80 04 90 00 } //5
		$a_01_1 = {64 65 6c 20 2f 66 20 2f 73 20 2f 71 } //1 del /f /s /q
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}