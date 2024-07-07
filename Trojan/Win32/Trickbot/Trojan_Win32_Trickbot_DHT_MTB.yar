
rule Trojan_Win32_Trickbot_DHT_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8b 44 24 18 83 c4 08 8a 54 14 14 32 da 88 5d 00 90 00 } //1
		$a_81_1 = {31 25 4f 42 7b 78 4c 75 4a 7d 4f 24 64 7e 43 64 23 76 54 7d 50 6d 64 7e 72 57 35 24 3f 30 4a 52 32 55 31 68 71 30 5a 31 } //1 1%OB{xLuJ}O$d~Cd#vT}Pmd~rW5$?0JR2U1hq0Z1
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}