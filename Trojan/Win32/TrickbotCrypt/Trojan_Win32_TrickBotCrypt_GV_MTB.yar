
rule Trojan_Win32_TrickBotCrypt_GV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e0 3b 45 f0 73 ?? 8b 4d e0 0f b6 11 0f b6 45 df 33 d0 8b 4d e0 2b 4d 08 0f b6 c1 83 e0 20 33 d0 8b 4d e0 88 11 8b 55 e0 03 55 fc 89 55 e0 eb } //10
		$a_81_1 = {4d 41 53 54 45 52 4b 45 59 56 41 4c 55 45 50 52 4f 56 41 45 53 32 35 36 } //1 MASTERKEYVALUEPROVAES256
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}