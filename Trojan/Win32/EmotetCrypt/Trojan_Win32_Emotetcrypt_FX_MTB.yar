
rule Trojan_Win32_Emotetcrypt_FX_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0a 33 c8 8b 15 90 01 04 0f af 15 90 01 04 a1 90 01 04 0f af 05 90 01 04 0f af 05 90 01 04 8b 75 90 01 01 2b 35 90 01 04 2b 35 90 01 04 2b 35 90 01 04 03 35 90 01 04 2b 35 90 01 04 2b 35 90 01 04 03 35 90 01 04 03 c6 03 05 90 01 04 03 c2 03 05 90 01 04 2b 05 90 01 04 8b 55 90 01 01 88 0c 02 90 00 } //01 00 
		$a_81_1 = {69 35 62 72 78 63 6b 69 64 21 3c 4f 2a 31 76 23 6e 45 61 45 4f 76 48 68 4b 75 6b 41 55 54 53 58 40 44 74 40 74 53 66 5a 21 77 49 24 32 79 55 67 50 72 28 45 4a 73 46 44 45 25 2a 21 6d 64 45 2a 6b 63 67 43 49 69 68 6d 76 26 66 65 5a 5f 56 3f 45 3c 39 47 5e 55 } //00 00  i5brxckid!<O*1v#nEaEOvHhKukAUTSX@Dt@tSfZ!wI$2yUgPr(EJsFDE%*!mdE*kcgCIihmv&feZ_V?E<9G^U
	condition:
		any of ($a_*)
 
}