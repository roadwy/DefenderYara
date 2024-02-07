
rule Trojan_Win32_Emotet_PBH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 90 01 04 0f b6 04 0a 8b 54 24 90 01 01 32 04 13 8b 54 24 90 01 01 88 04 13 90 00 } //01 00 
		$a_81_1 = {62 7e 65 62 64 6e 7e 78 6d 61 68 74 4f 47 48 64 35 56 6d 47 65 6a 70 6e 24 6e 66 36 4c 69 43 70 6f 68 36 67 56 69 4f 45 38 56 7a 4f 40 43 5a 63 35 40 6c 24 69 54 31 40 40 43 43 77 50 49 48 41 6f 47 43 4e 30 } //00 00  b~ebdn~xmahtOGHd5VmGejpn$nf6LiCpoh6gViOE8VzO@CZc5@l$iT1@@CCwPIHAoGCN0
	condition:
		any of ($a_*)
 
}