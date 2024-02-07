
rule Trojan_Win32_Tofsee_GMS_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 31 db 2b 1f f7 db 83 c7 04 f7 db 83 eb 26 83 eb 02 83 c3 01 29 cb 53 59 6a 00 8f 02 01 1a 83 c2 04 83 ee 04 83 fe 00 75 d7 } //01 00 
		$a_80_1 = {61 65 64 64 73 61 70 69 2e 64 6c 6c } //aeddsapi.dll  01 00 
		$a_01_2 = {65 6b 6a 69 6b 6c 6f 6d 6a 68 6e 62 67 74 79 76 66 64 65 72 63 76 62 78 73 71 61 } //01 00  ekjiklomjhnbgtyvfdercvbxsqa
		$a_01_3 = {61 6b 69 6d 64 68 63 7a 6b 74 79 } //00 00  akimdhczkty
	condition:
		any of ($a_*)
 
}