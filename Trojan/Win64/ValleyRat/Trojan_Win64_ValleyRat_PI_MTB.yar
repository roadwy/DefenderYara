
rule Trojan_Win64_ValleyRat_PI_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 69 61 69 33 36 30 2e 62 61 74 } //1 kiai360.bat
		$a_01_1 = {5a 68 69 4d 61 55 70 64 61 74 65 2e 64 6c 6c } //1 ZhiMaUpdate.dll
		$a_01_2 = {52 65 64 54 65 61 6d 4b 65 79 31 32 33 34 35 36 } //1 RedTeamKey123456
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}