
rule Trojan_Win64_LucaStealer_NC_MTB{
	meta:
		description = "Trojan:Win64/LucaStealer.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 84 a3 00 00 00 48 8d 55 e0 49 89 c1 49 89 d8 48 c7 44 24 38 ?? ?? ?? ?? 48 8d 0d dc 41 0d 00 48 89 54 24 ?? 48 8d 55 e8 48 89 4c 24 ?? 31 c9 48 89 54 24 28 } //5
		$a_01_1 = {3a 2f 2f 7a 64 76 2e 6c 69 66 65 2f 64 6f 77 6e 6c 6f 61 64 65 72 2e 65 78 65 } //1 ://zdv.life/downloader.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}