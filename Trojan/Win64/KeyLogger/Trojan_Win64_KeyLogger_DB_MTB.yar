
rule Trojan_Win64_KeyLogger_DB_MTB{
	meta:
		description = "Trojan:Win64/KeyLogger.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {f6 54 0d b0 48 ff c1 48 83 f9 1b 72 f3 4c 8d 45 b0 } //02 00 
		$a_01_1 = {0f b7 01 41 b9 ff ff 00 00 66 f7 d0 66 41 89 04 08 0f b7 01 48 8d 49 02 66 44 3b c8 } //00 00 
	condition:
		any of ($a_*)
 
}