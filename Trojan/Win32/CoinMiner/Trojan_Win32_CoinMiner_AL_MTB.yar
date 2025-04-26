
rule Trojan_Win32_CoinMiner_AL_MTB{
	meta:
		description = "Trojan:Win32/CoinMiner.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 03 83 f3 ?? fe cb 33 d9 64 a1 [0-04] 1b de 8b d0 02 f9 73 05 } //2
		$a_01_1 = {31 3a 8b df 2b d9 8b 32 21 eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}