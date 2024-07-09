
rule Trojan_Win32_Emotet_PEZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 02 8b 4d ?? 03 4d ?? 33 d2 8a 11 33 c2 8b 4d ?? 03 8d ?? ?? fe ff 88 01 } //1
		$a_81_1 = {35 24 25 7a 4d 78 7e 4b 53 4f 69 3f 67 7e 24 77 4c 68 43 79 37 4d 30 51 45 32 4d 61 51 2a 44 42 57 3f 72 39 44 6e 3f 75 25 4e 77 47 41 23 6d 53 68 37 6f 58 4d 53 7c 7c 25 2a 53 6b 54 79 23 67 7b 42 43 53 72 4d 78 3f 5a 71 7a 55 } //1 5$%zMx~KSOi?g~$wLhCy7M0QE2MaQ*DBW?r9Dn?u%NwGA#mSh7oXMS||%*SkTy#g{BCSrMx?ZqzU
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}