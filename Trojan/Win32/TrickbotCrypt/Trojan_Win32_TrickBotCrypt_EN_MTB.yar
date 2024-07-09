
rule Trojan_Win32_TrickBotCrypt_EN_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 c1 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 55 0c 8b 4d e4 8b 09 8b 75 08 33 db 8a 1c 0e 03 1d ?? ?? ?? ?? 8a 14 02 32 d3 } //1
		$a_81_1 = {39 72 63 37 2b 35 5f 23 50 6f 6b 78 32 30 43 24 35 50 38 78 64 76 41 6a 73 65 62 62 2b 4d 38 2b 39 63 4d 61 54 67 59 5a 4d 54 57 6f 3c 71 71 2b 6e 6d 5e 68 43 64 } //1 9rc7+5_#Pokx20C$5P8xdvAjsebb+M8+9cMaTgYZMTWo<qq+nm^hCd
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}