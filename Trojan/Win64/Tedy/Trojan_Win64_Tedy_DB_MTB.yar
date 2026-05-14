
rule Trojan_Win64_Tedy_DB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 63 c8 48 8d 14 24 48 03 d1 41 ff c3 0f b6 0a 41 88 0a 44 88 0a 45 02 0a 41 0f b6 c9 0f b6 14 0c 32 14 33 88 13 48 ff c3 49 63 cb 48 3b cd 72 } //10
		$a_81_1 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 68 77 69 64 2e 64 61 74 } //1 ProgramData\hwid.dat
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}