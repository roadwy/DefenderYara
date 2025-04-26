
rule Trojan_BAT_CryptInject_RH_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 44 41 52 4a 2e 6d 70 33 75 70 25 } //3 /DARJ.mp3up%
		$a_00_1 = {32 00 49 00 33 00 2d 00 34 00 2d 00 35 00 } //2 2I3-4-5
		$a_01_2 = {45 4e 45 5a 45 5a 66 46 46 64 78 } //1 ENEZEZfFFdx
		$a_01_3 = {2f 4b 41 52 4b 20 4e 45 57 2e 6d 70 33 50 4b } //1 /KARK NEW.mp3PK
		$a_01_4 = {2f 47 61 74 61 5f 51 75 64 72 69 5f 30 32 2e 6d 70 33 50 4b } //1 /Gata_Qudri_02.mp3PK
		$a_03_5 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 bc 13 00 00 6e d1 00 00 00 00 00 ae da 13 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2) >=10
 
}