
rule Trojan_Win32_TrickBot_SD_bit{
	meta:
		description = "Trojan:Win32/TrickBot.SD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 20 c7 45 f4 00 00 00 00 8b 45 f4 3b 45 10 74 3f 8b 55 0c 8b 45 f4 8d 1c 02 8b 55 0c 8b 45 f4 01 d0 0f b6 00 89 c6 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 89 c1 8b 45 f4 ba 00 00 00 00 f7 f1 8b 45 08 01 d0 0f b6 00 31 f0 88 03 83 45 f4 01 eb b9 [0-10] 83 c4 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}