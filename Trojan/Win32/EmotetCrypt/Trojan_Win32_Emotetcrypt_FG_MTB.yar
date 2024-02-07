
rule Trojan_Win32_Emotetcrypt_FG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 2f 03 c2 33 d2 f7 35 90 01 04 58 2b c1 0f af c3 03 d0 8b 44 24 90 01 01 2b d6 8a 0c 3a 30 08 ff 44 24 90 01 01 8b 44 24 90 01 01 3b 44 24 90 01 01 0f 82 90 00 } //01 00 
		$a_81_1 = {57 43 65 25 26 67 28 39 38 68 47 57 66 79 68 54 4e 70 76 62 3e 47 71 29 6a 78 52 5f 50 2a 57 68 65 38 68 43 5f 5e 5f 67 69 4b 42 6a 35 31 49 4a 45 35 3c 43 46 77 40 39 21 47 23 40 7a 4f 2b 69 47 6e 25 28 62 47 74 75 67 45 33 70 21 50 46 4b 78 65 58 57 54 62 63 6d 63 64 66 40 76 29 23 25 54 79 5a 71 23 71 5a 62 71 33 29 3c 4f 75 34 51 6a 30 33 54 4c } //00 00  WCe%&g(98hGWfyhTNpvb>Gq)jxR_P*Whe8hC_^_giKBj51IJE5<CFw@9!G#@zO+iGn%(bGtugE3p!PFKxeXWTbcmcdf@v)#%TyZq#qZbq3)<Ou4Qj03TL
	condition:
		any of ($a_*)
 
}