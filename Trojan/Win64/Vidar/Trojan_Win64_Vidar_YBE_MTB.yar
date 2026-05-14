
rule Trojan_Win64_Vidar_YBE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 61 6c 6c 65 74 49 44 } //1 WalletID
		$a_01_1 = {48 8b 94 24 60 03 00 00 48 01 c2 48 81 f2 aa 00 00 00 88 54 04 47 48 ff c0 48 83 f8 10 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}