
rule Trojan_Win64_DiscordStealer_SX_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 69 6c 65 6e 63 65 4c 6f 61 64 65 72 2f 31 2e 30 } //10 SilenceLoader/1.0
		$a_01_1 = {53 69 6c 65 6e 63 65 20 44 6c 6c } //10 Silence Dll
		$a_01_2 = {5c 43 6f 72 65 5c 4d 69 6c 69 74 61 72 79 43 72 79 70 74 6f 2e 68 70 70 } //5 \Core\MilitaryCrypto.hpp
		$a_01_3 = {6e 6f 5f 6c 69 63 65 6e 73 65 5f 62 73 6f 64 } //5 no_license_bsod
		$a_01_4 = {2f 7a 36 76 32 62 39 74 34 } //2 /z6v2b9t4
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*2) >=32
 
}