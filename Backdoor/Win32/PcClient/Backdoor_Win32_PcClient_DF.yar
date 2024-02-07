
rule Backdoor_Win32_PcClient_DF{
	meta:
		description = "Backdoor:Win32/PcClient.DF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0b 00 00 02 00 "
		
	strings :
		$a_02_0 = {ff ff 00 eb 0d 8b 85 90 01 02 ff ff 40 89 85 90 01 02 ff ff 83 bd 90 01 02 ff ff 06 7d 37 ff 15 90 01 04 99 6a 1a 59 f7 f9 8b 85 90 01 02 ff ff 88 94 90 01 02 fd ff ff 8b 85 90 01 02 ff ff 8a 84 90 01 02 fd ff ff 04 61 90 00 } //02 00 
		$a_02_1 = {50 8b 45 08 05 f4 03 00 00 50 68 90 01 04 e8 90 01 02 00 00 83 c4 0c c6 85 90 01 02 ff ff 08 c6 85 90 01 02 ff ff 08 c6 85 90 01 02 ff ff 04 c6 85 90 01 02 ff ff 02 83 65 fc 00 ff 75 08 8b 45 08 05 06 05 00 00 50 90 00 } //02 00 
		$a_00_2 = {53 65 72 76 69 63 65 38 38 } //01 00  Service88
		$a_00_3 = {77 77 77 2e 78 75 68 61 63 6b 2e 63 6e 2f 31 2e 74 78 74 } //01 00  www.xuhack.cn/1.txt
		$a_00_4 = {25 73 25 30 37 78 2e 6c 6f 67 } //01 00  %s%07x.log
		$a_00_5 = {47 6c 6f 62 61 6c 5c 43 73 25 30 36 78 } //01 00  Global\Cs%06x
		$a_00_6 = {5c 53 56 43 48 4f 53 54 2e 45 58 45 } //01 00  \SVCHOST.EXE
		$a_00_7 = {44 52 49 56 45 52 53 5c } //01 00  DRIVERS\
		$a_00_8 = {2e 4b 45 59 } //01 00  .KEY
		$a_00_9 = {2e 73 63 6f } //01 00  .sco
		$a_00_10 = {2e 70 72 6f } //00 00  .pro
	condition:
		any of ($a_*)
 
}