
rule Trojan_Win32_Emotet_PSU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8a 54 14 90 01 01 32 da 88 5d 00 90 00 } //1
		$a_81_1 = {79 77 66 54 47 74 43 4d 67 77 52 4a 74 67 65 55 70 6d 36 72 39 30 63 39 51 31 67 6b 78 4a 53 51 4e 33 32 4c 6e 77 47 49 77 41 45 } //1 ywfTGtCMgwRJtgeUpm6r90c9Q1gkxJSQN32LnwGIwAE
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}