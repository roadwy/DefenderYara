
rule Trojan_MacOS_OpinionSpy_A_xp{
	meta:
		description = "Trojan:MacOS/OpinionSpy.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 09 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //02 00  securestudies.com
		$a_02_1 = {6d 61 63 6d 65 74 65 72 32 2f 90 02 08 2f 4d 61 63 41 6e 61 6c 79 73 65 72 2f 90 00 } //02 00 
		$a_00_2 = {77 77 77 2e 70 72 65 6d 69 65 72 6f 70 69 6e 69 6f 6e 2e 63 6f 6d } //02 00  www.premieropinion.com
		$a_00_3 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 50 6f 50 61 74 68 78 44 2f 70 6f 69 6e 73 74 61 6c 6c 65 72 } //02 00  /private/tmp/PoPathxD/poinstaller
		$a_00_4 = {63 6f 6d 2e 56 6f 69 63 65 46 69 76 65 2e 50 72 65 6d 69 65 72 4f 70 69 6e 69 6f 6e } //02 00  com.VoiceFive.PremierOpinion
		$a_00_5 = {51 54 43 38 41 58 47 4c 34 34 } //01 00  QTC8AXGL44
		$a_00_6 = {63 61 6d 70 61 69 67 6e 5f 69 64 3d } //01 00  campaign_id=
		$a_00_7 = {75 73 72 2f 73 62 69 6e 2f 6c 73 6f 66 20 2d 61 20 2d 70 20 25 64 20 2b 44 20 25 73 } //01 00  usr/sbin/lsof -a -p %d +D %s
		$a_00_8 = {2f 74 6d 70 2f 74 6d 70 46 69 6c 65 2e 58 58 58 58 58 58 } //00 00  /tmp/tmpFile.XXXXXX
		$a_00_9 = {5d 04 00 } //00 93 
	condition:
		any of ($a_*)
 
}